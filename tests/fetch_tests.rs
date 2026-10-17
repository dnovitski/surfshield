//! Integration tests against a local mock server. No external network access is used.

use std::time::Duration;

use base64::Engine;
use reqwest::Method;
use surfshield::config::Config;
use surfshield::error::{FetchError, PolicyError};
use surfshield::fetch::{Fetcher, RequestBody};
use surfshield::output::{self, BodyEncoding, Format};
use wiremock::matchers::{body_string, header, header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The mock server listens on loopback, so tests opt in to private addresses.
fn local_config() -> Config {
    let mut config = Config::default();
    config.policy.allow_private_ips = true;
    config
}

fn fetcher(config: &Config) -> Fetcher {
    Fetcher::new(config).unwrap()
}

async fn get(config: &Config, url: &str) -> Result<surfshield::fetch::FetchResponse, FetchError> {
    fetcher(config).fetch(Method::GET, url, &[]).await
}

#[tokio::test]
async fn raw_body_is_byte_identical() {
    let server = MockServer::start().await;
    // Latin-1 encoded HTML: not valid UTF-8, odd whitespace and CRLF line endings.
    let mut body = b"<!DOCTYPE html>\r\n<html>  <body>\tcaf".to_vec();
    body.push(0xe9);
    body.extend_from_slice(b"  </body></html>\r\n");
    Mock::given(method("GET"))
        .and(path("/latin1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(body.clone(), "text/html; charset=iso-8859-1"),
        )
        .mount(&server)
        .await;

    let response = get(&local_config(), &format!("{}/latin1", server.uri()))
        .await
        .unwrap();
    assert_eq!(response.body, body);

    let rendered = output::render(&response, Format::Raw, 100_000);
    assert_eq!(rendered.encoding, BodyEncoding::Base64);
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(rendered.text.unwrap())
        .unwrap();
    assert_eq!(decoded, body);

    // Markdown mode decodes the declared charset.
    let markdown = output::render(&response, Format::Markdown, 100_000);
    assert!(markdown.text.unwrap().contains("café"));
}

#[tokio::test]
async fn raw_utf8_html_is_returned_exactly() {
    let server = MockServer::start().await;
    let html = "<!doctype html>\n<html><head><script>var x = 1;</script></head>\n<body><p class=\"a\">  Hé  </p></body></html>\n";
    Mock::given(path("/page"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(html, "text/html"))
        .mount(&server)
        .await;

    let response = get(&local_config(), &format!("{}/page", server.uri()))
        .await
        .unwrap();
    let rendered = output::render(&response, Format::Raw, 100_000);
    assert_eq!(rendered.encoding, BodyEncoding::Text);
    assert_eq!(rendered.text.as_deref(), Some(html));

    let markdown = output::render(&response, Format::Markdown, 100_000)
        .text
        .unwrap();
    assert!(markdown.contains("Hé"));
    assert!(!markdown.contains("var x"));
}

#[tokio::test]
async fn binary_content_in_markdown_mode_gives_a_note() {
    let server = MockServer::start().await;
    Mock::given(path("/img"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(vec![0x89, b'P', b'N', b'G'], "image/png"),
        )
        .mount(&server)
        .await;
    let response = get(&local_config(), &format!("{}/img", server.uri()))
        .await
        .unwrap();
    let rendered = output::render(&response, Format::Markdown, 100_000);
    assert!(rendered.text.is_none());
    assert!(rendered.note.unwrap().contains("image/png"));
}

#[tokio::test]
async fn follows_redirects_and_records_them() {
    let server = MockServer::start().await;
    Mock::given(path("/a"))
        .respond_with(ResponseTemplate::new(301).insert_header("Location", "/b"))
        .mount(&server)
        .await;
    Mock::given(path("/b"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "c"))
        .mount(&server)
        .await;
    Mock::given(path("/c"))
        .respond_with(ResponseTemplate::new(200).set_body_string("done"))
        .mount(&server)
        .await;

    let response = get(&local_config(), &format!("{}/a", server.uri()))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"done");
    assert_eq!(response.final_url.path(), "/c");
    assert_eq!(response.redirects.len(), 2);
}

#[tokio::test]
async fn redirect_to_denied_domain_is_blocked() {
    let server = MockServer::start().await;
    Mock::given(path("/go"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", "http://forbidden.test/secret"),
        )
        .mount(&server)
        .await;
    let mut config = local_config();
    config.policy.denied_domains = vec!["*.forbidden.test".into()];

    let err = get(&config, &format!("{}/go", server.uri()))
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::Policy(PolicyError::DomainDenied(_))),
        "{err}"
    );
}

#[tokio::test]
async fn too_many_redirects() {
    let server = MockServer::start().await;
    Mock::given(path("/loop"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/loop"))
        .mount(&server)
        .await;
    let err = get(&local_config(), &format!("{}/loop", server.uri()))
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::TooManyRedirects(5)), "{err}");
}

#[tokio::test]
async fn credentials_are_stripped_on_cross_origin_redirect() {
    let origin = MockServer::start().await;
    let other = MockServer::start().await;

    Mock::given(path("/same"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/landing"))
        .mount(&origin)
        .await;
    Mock::given(path("/landing"))
        .and(header("authorization", "Bearer secret"))
        .respond_with(ResponseTemplate::new(200).set_body_string("kept"))
        .mount(&origin)
        .await;
    Mock::given(path("/cross"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/landing", other.uri())),
        )
        .mount(&origin)
        .await;
    Mock::given(path("/landing"))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(500).set_body_string("leaked"))
        .mount(&other)
        .await;
    Mock::given(path("/landing"))
        .and(header("x-custom", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_string("stripped"))
        .mount(&other)
        .await;

    let config = local_config();
    let headers = vec![
        ("Authorization".to_string(), "Bearer secret".to_string()),
        ("X-Custom".to_string(), "1".to_string()),
    ];
    let fetcher = fetcher(&config);

    let same = fetcher
        .fetch(Method::GET, &format!("{}/same", origin.uri()), &headers)
        .await
        .unwrap();
    assert_eq!(same.body, b"kept");

    let cross = fetcher
        .fetch(Method::GET, &format!("{}/cross", origin.uri()), &headers)
        .await
        .unwrap();
    assert_eq!(cross.body, b"stripped");
}

#[tokio::test]
async fn custom_headers_are_sent_and_override_user_agent() {
    let server = MockServer::start().await;
    Mock::given(path("/h"))
        .and(header("accept", "application/json"))
        .and(header("user-agent", "my-agent/1.0"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{\"ok\":true}"))
        .mount(&server)
        .await;
    Mock::given(path("/ua"))
        .and(header(
            "user-agent",
            concat!("surfshield/", env!("CARGO_PKG_VERSION")),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string("default"))
        .mount(&server)
        .await;

    let config = local_config();
    let headers = vec![
        ("Accept".to_string(), "application/json".to_string()),
        ("User-Agent".to_string(), "my-agent/1.0".to_string()),
    ];
    let response = fetcher(&config)
        .fetch(Method::GET, &format!("{}/h", server.uri()), &headers)
        .await
        .unwrap();
    assert_eq!(response.status, 200);

    let response = get(&config, &format!("{}/ua", server.uri())).await.unwrap();
    assert_eq!(response.body, b"default");
}

#[tokio::test]
async fn denied_request_header_is_rejected_before_sending() {
    let config = local_config();
    let headers = vec![("Host".to_string(), "evil.example".to_string())];
    let err = fetcher(&config)
        .fetch(Method::GET, "http://127.0.0.1:1/", &headers)
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::Policy(PolicyError::HeaderDenied(_))),
        "{err}"
    );
}

#[tokio::test]
async fn body_is_truncated_at_max_body_bytes() {
    let server = MockServer::start().await;
    Mock::given(path("/big"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 5000]))
        .mount(&server)
        .await;
    let mut config = local_config();
    config.limits.max_body_bytes = 1000;

    let response = get(&config, &format!("{}/big", server.uri()))
        .await
        .unwrap();
    assert!(response.body_truncated);
    assert_eq!(response.body.len(), 1000);

    let dir = tempfile::tempdir().unwrap();
    assert!(output::save_body(&response, &dir.path().join("big"), false).is_err());
}

#[tokio::test]
async fn total_timeout() {
    let server = MockServer::start().await;
    Mock::given(path("/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;
    let mut config = local_config();
    config.limits.total_timeout_secs = 1;

    let err = get(&config, &format!("{}/slow", server.uri()))
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::Timeout(1)), "{err}");
}

#[tokio::test]
async fn loopback_is_blocked_by_default() {
    let server = MockServer::start().await;
    Mock::given(path("/"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let config = Config::default();
    let port = server.address().port();

    let err = get(&config, &server.uri()).await.unwrap_err();
    assert!(
        matches!(err, FetchError::Policy(PolicyError::AddressBlocked(_))),
        "{err}"
    );

    // A hostname is checked after DNS resolution.
    let err = get(&config, &format!("http://localhost:{port}/"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::Policy(PolicyError::AllAddressesBlocked(_))),
        "{err}"
    );
}

#[tokio::test]
async fn head_returns_headers_without_body() {
    let server = MockServer::start().await;
    Mock::given(method("HEAD"))
        .and(path("/doc"))
        .respond_with(ResponseTemplate::new(200).insert_header("x-version", "42"))
        .mount(&server)
        .await;
    let response = fetcher(&local_config())
        .fetch(Method::HEAD, &format!("{}/doc", server.uri()), &[])
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.headers["x-version"], "42");
    assert!(response.body.is_empty());
}

fn post_body(json: &str) -> Option<RequestBody> {
    Some(RequestBody::new(json, Some("application/json")))
}

#[tokio::test]
async fn post_sends_body_and_content_type() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/json"))
        .and(header("content-type", "application/json"))
        .and(body_string(r#"{"a":1}"#))
        .respond_with(ResponseTemplate::new(201).set_body_string("created"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/form"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string("q=caf%C3%A9+au+lait&n=1%262"))
        .respond_with(ResponseTemplate::new(200).set_body_string("form"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/custom"))
        .and(header("content-type", "text/csv"))
        .respond_with(ResponseTemplate::new(200).set_body_string("csv"))
        .mount(&server)
        .await;

    let config = local_config();
    let fetcher = fetcher(&config);
    let response = fetcher
        .fetch_with_body(
            Method::POST,
            &format!("{}/json", server.uri()),
            &[],
            post_body(r#"{"a":1}"#),
        )
        .await
        .unwrap();
    assert_eq!(response.status, 201);

    let form = RequestBody::form([("q", "café au lait"), ("n", "1&2")]);
    let response = fetcher
        .fetch_with_body(
            Method::POST,
            &format!("{}/form", server.uri()),
            &[],
            Some(form),
        )
        .await
        .unwrap();
    assert_eq!(response.body, b"form");

    // A Content-Type header from the caller wins over the body's default.
    let headers = vec![("Content-Type".to_string(), "text/csv".to_string())];
    let response = fetcher
        .fetch_with_body(
            Method::POST,
            &format!("{}/custom", server.uri()),
            &headers,
            post_body("a,b"),
        )
        .await
        .unwrap();
    assert_eq!(response.body, b"csv");
}

#[tokio::test]
async fn post_redirects_follow_browser_rules() {
    let server = MockServer::start().await;
    Mock::given(path("/see-other"))
        .respond_with(ResponseTemplate::new(303).insert_header("Location", "/result"))
        .mount(&server)
        .await;
    Mock::given(path("/temporary"))
        .respond_with(ResponseTemplate::new(307).insert_header("Location", "/echo"))
        .mount(&server)
        .await;
    // 303: the follow-up is a GET without body or Content-Type.
    Mock::given(method("GET"))
        .and(path("/result"))
        .and(|req: &wiremock::Request| {
            req.body.is_empty() && !req.headers.contains_key("content-type")
        })
        .respond_with(ResponseTemplate::new(200).set_body_string("result"))
        .mount(&server)
        .await;
    // 307: method and body are repeated.
    Mock::given(method("POST"))
        .and(path("/echo"))
        .and(body_string("payload"))
        .respond_with(ResponseTemplate::new(200).set_body_string("echoed"))
        .mount(&server)
        .await;

    let config = local_config();
    let fetcher = fetcher(&config);
    let response = fetcher
        .fetch_with_body(
            Method::POST,
            &format!("{}/see-other", server.uri()),
            &[],
            post_body("payload"),
        )
        .await
        .unwrap();
    assert_eq!(response.body, b"result");

    let response = fetcher
        .fetch_with_body(
            Method::POST,
            &format!("{}/temporary", server.uri()),
            &[],
            post_body("payload"),
        )
        .await
        .unwrap();
    assert_eq!(response.body, b"echoed");
    assert_eq!(response.redirects.len(), 1);
}

#[tokio::test]
async fn post_body_is_not_resent_to_another_origin() {
    let origin = MockServer::start().await;
    let other = MockServer::start().await;
    Mock::given(path("/move"))
        .respond_with(
            ResponseTemplate::new(308).insert_header("Location", format!("{}/steal", other.uri())),
        )
        .mount(&origin)
        .await;
    Mock::given(path("/steal"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&other)
        .await;

    let err = fetcher(&local_config())
        .fetch_with_body(
            Method::POST,
            &format!("{}/move", origin.uri()),
            &[],
            post_body("secret"),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::CrossOriginRedirect { .. }),
        "{err}"
    );
}

#[tokio::test]
async fn post_limits_and_method_policy() {
    let mut config = local_config();
    config.limits.max_request_body_bytes = 4;
    let err = fetcher(&config)
        .fetch_with_body(Method::POST, "http://127.0.0.1:1/", &[], post_body("12345"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::Policy(PolicyError::RequestBodyTooLarge(4))),
        "{err}"
    );

    let mut config = local_config();
    config.policy.allowed_methods = vec!["GET".into(), "HEAD".into()];
    let err = fetcher(&config)
        .fetch_with_body(Method::POST, "http://127.0.0.1:1/", &[], post_body("{}"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::Policy(PolicyError::MethodNotAllowed(_))),
        "{err}"
    );
}

#[tokio::test]
async fn put_patch_and_delete_send_method_and_body() {
    let server = MockServer::start().await;
    for verb in ["PUT", "PATCH", "DELETE"] {
        Mock::given(method(verb))
            .and(path("/item"))
            .and(header("content-type", "application/json"))
            .and(body_string(r#"{"v":2}"#))
            .respond_with(ResponseTemplate::new(200).set_body_string(verb))
            .mount(&server)
            .await;
    }
    // Without a body, DELETE sends none at all (no Content-Type, no Content-Length).
    Mock::given(method("DELETE"))
        .and(path("/bare"))
        .and(|req: &wiremock::Request| {
            req.body.is_empty()
                && !req.headers.contains_key("content-type")
                && !req.headers.contains_key("content-length")
        })
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    // PUT without a body still sends Content-Length: 0.
    Mock::given(method("PUT"))
        .and(path("/bare"))
        .and(header("content-length", "0"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let config = local_config();
    let fetcher = fetcher(&config);
    for (verb, m) in [
        ("PUT", Method::PUT),
        ("PATCH", Method::PATCH),
        ("DELETE", Method::DELETE),
    ] {
        let response = fetcher
            .fetch_with_body(
                m,
                &format!("{}/item", server.uri()),
                &[],
                post_body(r#"{"v":2}"#),
            )
            .await
            .unwrap();
        assert_eq!(response.body, verb.as_bytes());
    }
    for m in [Method::DELETE, Method::PUT] {
        let response = fetcher
            .fetch_with_body(m.clone(), &format!("{}/bare", server.uri()), &[], None)
            .await
            .unwrap();
        assert_eq!(response.status, 204, "{m}");
    }
}

#[tokio::test]
async fn redirects_for_put_and_delete() {
    let server = MockServer::start().await;
    // 301 only turns POST into GET; PUT keeps its method and body.
    Mock::given(path("/old"))
        .respond_with(ResponseTemplate::new(301).insert_header("Location", "/new"))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/new"))
        .and(body_string("data"))
        .respond_with(ResponseTemplate::new(200).set_body_string("put"))
        .mount(&server)
        .await;
    // 303 turns any method into GET.
    Mock::given(path("/gone"))
        .respond_with(ResponseTemplate::new(303).insert_header("Location", "/status"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200).set_body_string("deleted"))
        .mount(&server)
        .await;

    let config = local_config();
    let fetcher = fetcher(&config);
    let response = fetcher
        .fetch_with_body(
            Method::PUT,
            &format!("{}/old", server.uri()),
            &[],
            post_body("data"),
        )
        .await
        .unwrap();
    assert_eq!(response.body, b"put");
    let response = fetcher
        .fetch_with_body(Method::DELETE, &format!("{}/gone", server.uri()), &[], None)
        .await
        .unwrap();
    assert_eq!(response.body, b"deleted");
}

#[tokio::test]
async fn delete_is_not_repeated_at_another_origin() {
    let origin = MockServer::start().await;
    let other = MockServer::start().await;
    Mock::given(path("/res"))
        .respond_with(
            ResponseTemplate::new(307).insert_header("Location", format!("{}/res", other.uri())),
        )
        .mount(&origin)
        .await;
    Mock::given(path("/res"))
        .respond_with(ResponseTemplate::new(204))
        .expect(0)
        .mount(&other)
        .await;

    let err = fetcher(&local_config())
        .fetch_with_body(Method::DELETE, &format!("{}/res", origin.uri()), &[], None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::CrossOriginRedirect { .. }),
        "{err}"
    );

    let mut config = local_config();
    config.policy.allowed_methods = vec!["GET".into(), "POST".into()];
    let err = fetcher(&config)
        .fetch_with_body(Method::DELETE, &format!("{}/res", origin.uri()), &[], None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::Policy(PolicyError::MethodNotAllowed(_))),
        "{err}"
    );
}
