//! Proxy tests against a local socks5 proxy and mock server. No external network access is used.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use reqwest::Method;
use surfshield::config::Config;
use surfshield::error::{FetchError, PolicyError};
use surfshield::fetch::{FetchResponse, Fetcher};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wiremock::matchers::{header, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The destination a client asked the proxy for.
#[derive(Debug, Clone, PartialEq)]
enum Target {
    Domain(String, u16),
    Ip(IpAddr, u16),
}

/// A minimal socks5 proxy on loopback: it records every CONNECT target and
/// forwards the connection to `upstream`, whatever the target was.
async fn socks5_proxy(upstream: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<Target>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let targets = Arc::new(Mutex::new(Vec::new()));
    let recorded = targets.clone();
    tokio::spawn(async move {
        loop {
            let (conn, _) = listener.accept().await.unwrap();
            let recorded = recorded.clone();
            tokio::spawn(async move {
                let _ = serve_socks5(conn, upstream, recorded).await;
            });
        }
    });
    (addr, targets)
}

async fn serve_socks5(
    mut conn: TcpStream,
    upstream: SocketAddr,
    targets: Arc<Mutex<Vec<Target>>>,
) -> std::io::Result<()> {
    let mut hdr = [0u8; 2];
    conn.read_exact(&mut hdr).await?;
    let mut methods = vec![0u8; hdr[1] as usize];
    conn.read_exact(&mut methods).await?;
    conn.write_all(&[5, 0]).await?;

    let mut req = [0u8; 4];
    conn.read_exact(&mut req).await?;
    let target = match req[3] {
        1 => {
            let mut ip = [0u8; 4];
            conn.read_exact(&mut ip).await?;
            Target::Ip(IpAddr::from(ip), conn.read_u16().await?)
        }
        4 => {
            let mut ip = [0u8; 16];
            conn.read_exact(&mut ip).await?;
            Target::Ip(IpAddr::from(ip), conn.read_u16().await?)
        }
        3 => {
            let mut name = vec![0u8; conn.read_u8().await? as usize];
            conn.read_exact(&mut name).await?;
            Target::Domain(String::from_utf8(name).unwrap(), conn.read_u16().await?)
        }
        other => panic!("unexpected address type {other}"),
    };
    targets.lock().unwrap().push(target);

    let mut up = TcpStream::connect(upstream).await?;
    conn.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    tokio::io::copy_bidirectional(&mut conn, &mut up).await?;
    Ok(())
}

/// The default policy (no private addresses), with a proxy.
fn proxy_config(proxy: String) -> Config {
    let mut config = Config::default();
    config.http.proxy = Some(proxy);
    config.validate().unwrap();
    config
}

async fn get(config: &Config, url: &str) -> Result<FetchResponse, FetchError> {
    Fetcher::new(config)
        .unwrap()
        .fetch(Method::GET, url, &[])
        .await
}

async fn hello_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(path("/hello"))
        .respond_with(ResponseTemplate::new(200).set_body_string("hi"))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn socks5h_passes_the_hostname_to_the_proxy() {
    let server = hello_server().await;
    let (proxy, targets) = socks5_proxy(*server.address()).await;
    // The proxy is on loopback, yet reachable under the default policy: it was
    // configured explicitly as an IP address.
    let config = proxy_config(format!("socks5h://{proxy}"));

    // example.test does not resolve; only the proxy sees the name.
    let response = get(&config, "http://example.test/hello").await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hi");
    assert_eq!(
        *targets.lock().unwrap(),
        [Target::Domain("example.test".into(), 80)]
    );
}

#[tokio::test]
async fn socks5_resolves_locally_and_applies_the_address_policy() {
    let server = hello_server().await;
    let (proxy, targets) = socks5_proxy(*server.address()).await;
    let config = proxy_config(format!("socks5://{proxy}"));

    let err = get(&config, "http://localhost/hello").await.unwrap_err();
    assert!(
        matches!(err, FetchError::Policy(PolicyError::AllAddressesBlocked(_))),
        "{err}"
    );
    assert!(targets.lock().unwrap().is_empty());
}

#[tokio::test]
async fn socks5_sends_the_checked_address_to_the_proxy() {
    let server = hello_server().await;
    let (proxy, targets) = socks5_proxy(*server.address()).await;
    let mut config = proxy_config(format!("socks5://{proxy}"));
    config.policy.allow_private_ips = true;

    let response = get(&config, "http://localhost:8080/hello").await.unwrap();
    assert_eq!(response.body, b"hi");
    let targets = targets.lock().unwrap();
    assert!(
        matches!(targets[..], [Target::Ip(ip, 8080)] if ip.is_loopback()),
        "{targets:?}"
    );
}

#[tokio::test]
async fn url_checks_still_apply_through_a_proxy() {
    let server = hello_server().await;
    let (proxy, targets) = socks5_proxy(*server.address()).await;
    let mut config = proxy_config(format!("socks5h://{proxy}"));
    config.policy.denied_domains = vec!["*.denied.test".into()];

    let err = get(&config, "http://10.0.0.1/hello").await.unwrap_err();
    assert!(
        matches!(err, FetchError::Policy(PolicyError::AddressBlocked(_))),
        "{err}"
    );
    let err = get(&config, "http://www.denied.test/hello")
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::Policy(PolicyError::DomainDenied(_))),
        "{err}"
    );
    assert!(targets.lock().unwrap().is_empty());
}

#[tokio::test]
async fn http_proxy_receives_the_request() {
    // The mock server acts as the proxy: it gets the absolute-form request.
    let proxy = MockServer::start().await;
    Mock::given(path("/via-proxy"))
        .and(header("host", "example.test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("proxied"))
        .mount(&proxy)
        .await;
    let config = proxy_config(proxy.uri());

    let response = get(&config, "http://example.test/via-proxy").await.unwrap();
    assert_eq!(response.body, b"proxied");
}

#[tokio::test]
async fn unreachable_proxy_is_an_error() {
    // Bind and drop a listener to get a port that refuses connections.
    let port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = proxy_config(format!("socks5h://127.0.0.1:{port}"));

    let err = get(&config, "http://example.test/").await.unwrap_err();
    assert!(matches!(err, FetchError::Http(_)), "{err}");
}
