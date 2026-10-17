use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::{self, HeaderMap};
use reqwest::{Method, StatusCode};
use url::Url;

use crate::config::{Config, LimitsConfig};
use crate::error::{BlockedHost, FetchError, PolicyError};
use crate::policy::Policy;

/// Headers that must not follow a redirect to a different origin.
const CREDENTIAL_HEADERS: [header::HeaderName; 3] = [
    header::AUTHORIZATION,
    header::COOKIE,
    header::PROXY_AUTHORIZATION,
];

/// Headers that describe the request body and are dropped when a redirect turns
/// the request into a GET without a body.
const BODY_HEADERS: [header::HeaderName; 4] = [
    header::CONTENT_TYPE,
    header::CONTENT_ENCODING,
    header::CONTENT_LANGUAGE,
    header::CONTENT_LOCATION,
];

/// A request body, sent exactly as given.
#[derive(Debug, Clone, Default)]
pub struct RequestBody {
    pub bytes: Vec<u8>,
    /// Sent as `Content-Type` unless the caller set that header itself.
    pub content_type: Option<String>,
}

impl RequestBody {
    pub fn new(bytes: impl Into<Vec<u8>>, content_type: Option<&str>) -> Self {
        Self {
            bytes: bytes.into(),
            content_type: content_type.map(String::from),
        }
    }

    pub fn json(value: &serde_json::Value) -> Self {
        Self::new(value.to_string(), Some("application/json"))
    }

    pub fn form<'a>(fields: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        Self::new(encoded, Some("application/x-www-form-urlencoded"))
    }
}

#[derive(Debug)]
pub struct FetchResponse {
    pub status: StatusCode,
    pub final_url: Url,
    /// URLs that answered with a redirect, in order.
    pub redirects: Vec<Url>,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    /// Set when the body was cut off at `max_body_bytes`.
    pub body_truncated: bool,
}

impl FetchResponse {
    pub fn content_type(&self) -> Option<&str> {
        self.headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
    }
}

pub struct Fetcher {
    client: reqwest::Client,
    policy: Arc<Policy>,
    limits: LimitsConfig,
}

impl Fetcher {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let policy = Arc::new(Policy::new(config.policy.clone(), config.limits.clone()));
        let mut builder = reqwest::Client::builder()
            // Redirects are followed manually so every hop passes the policy.
            .redirect(reqwest::redirect::Policy::none())
            // Ignore HTTP(S)_PROXY and the system proxy; only an explicitly
            // configured proxy is used.
            .no_proxy()
            .referer(false)
            .connect_timeout(Duration::from_secs(config.limits.connect_timeout_secs))
            .user_agent(&config.http.user_agent)
            .dns_resolver(PolicyResolver {
                policy: policy.clone(),
            });
        // With socks5 the target is resolved here by PolicyResolver, so the address
        // checks still apply. With socks5h and http the proxy resolves it, and only
        // the URL checks (scheme, denylist, ports, IP literals) apply.
        // The proxy itself is an IP address (see config), so it is reached
        // directly without PolicyResolver.
        if let Some(proxy) = &config.http.proxy {
            builder = builder.proxy(reqwest::Proxy::all(proxy.as_str())?);
        }
        let client = builder.build()?;
        Ok(Self {
            client,
            policy,
            limits: config.limits.clone(),
        })
    }

    pub async fn fetch(
        &self,
        method: Method,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<FetchResponse, FetchError> {
        self.fetch_with_body(method, url, headers, None).await
    }

    pub async fn fetch_with_body(
        &self,
        method: Method,
        url: &str,
        headers: &[(String, String)],
        body: Option<RequestBody>,
    ) -> Result<FetchResponse, FetchError> {
        let secs = self.limits.total_timeout_secs;
        tokio::time::timeout(
            Duration::from_secs(secs),
            self.fetch_inner(method, url, headers, body),
        )
        .await
        .map_err(|_| FetchError::Timeout(secs))?
    }

    async fn fetch_inner(
        &self,
        mut method: Method,
        url: &str,
        headers: &[(String, String)],
        body: Option<RequestBody>,
    ) -> Result<FetchResponse, FetchError> {
        let mut url = Url::parse(url)?;
        // POST, PUT and PATCH always carry a body, if only an empty one
        // (Content-Length: 0, which some servers require).
        let mut body = body.or_else(|| {
            matches!(method, Method::POST | Method::PUT | Method::PATCH).then(RequestBody::default)
        });
        let mut request_headers = self
            .policy
            .build_request_headers(headers.iter().map(|(k, v)| (k.as_str(), v.as_str())))?;
        if let Some(body) = &body {
            self.policy.check_request_body(&body.bytes)?;
            if let Some(content_type) = &body.content_type
                && !request_headers.contains_key(header::CONTENT_TYPE)
            {
                let value = header::HeaderValue::from_str(content_type)
                    .map_err(|_| PolicyError::InvalidHeaderValue("content-type".into()))?;
                request_headers.insert(header::CONTENT_TYPE, value);
            }
        }
        let mut redirects = Vec::new();

        loop {
            self.policy.check_method(&method)?;
            self.policy.check_url(&url)?;
            let mut request = self
                .client
                .request(method.clone(), url.clone())
                .headers(request_headers.clone());
            if let Some(body) = &body {
                // reqwest leaves Content-Length out for an empty body.
                if body.bytes.is_empty() {
                    request = request.header(header::CONTENT_LENGTH, 0);
                }
                request = request.body(body.bytes.clone());
            }
            let response = request.send().await.map_err(FetchError::from_reqwest)?;

            if let Some(location) = redirect_location(&response) {
                if redirects.len() >= self.limits.max_redirects {
                    return Err(FetchError::TooManyRedirects(self.limits.max_redirects));
                }
                let next = url
                    .join(location)
                    .map_err(|_| FetchError::InvalidRedirect)?;
                // Like browsers: 303 always becomes GET, and so do 301/302 after a
                // POST. 307 and 308 repeat the request with method and body.
                let status = response.status();
                if (status == StatusCode::SEE_OTHER && method != Method::HEAD)
                    || (method == Method::POST
                        && matches!(status, StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND))
                {
                    method = Method::GET;
                    if body.take().is_some() {
                        for name in &BODY_HEADERS {
                            request_headers.remove(name);
                        }
                    }
                }
                if next.origin() != url.origin() {
                    // A state-changing request is never repeated at another origin: its
                    // effect is meant for this site, and the body may carry credentials
                    // just like the stripped headers.
                    if body.is_some() || !matches!(method, Method::GET | Method::HEAD) {
                        return Err(FetchError::CrossOriginRedirect {
                            method: method.to_string(),
                            url: next.to_string(),
                        });
                    }
                    for name in &CREDENTIAL_HEADERS {
                        request_headers.remove(name);
                    }
                }
                redirects.push(std::mem::replace(&mut url, next));
                continue;
            }

            let status = response.status();
            let headers = response.headers().clone();
            let (body, body_truncated) = if method == Method::HEAD {
                (Vec::new(), false)
            } else {
                read_body(response, self.limits.max_body_bytes).await?
            };
            return Ok(FetchResponse {
                status,
                final_url: url,
                redirects,
                headers,
                body,
                body_truncated,
            });
        }
    }
}

fn redirect_location(response: &reqwest::Response) -> Option<&str> {
    let is_redirect = matches!(
        response.status(),
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    );
    if !is_redirect {
        return None;
    }
    response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
}

/// Streams the body, stopping once `max_bytes` is reached.
async fn read_body(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<(Vec<u8>, bool), FetchError> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(FetchError::from_reqwest)?;
        let remaining = max_bytes - body.len();
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            return Ok((body, true));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, false))
}

/// Resolves hostnames and drops every address the policy does not allow. Because
/// reqwest connects to exactly the addresses returned here, a DNS answer cannot
/// change between the check and the connection (DNS rebinding).
struct PolicyResolver {
    policy: Arc<Policy>,
}

impl Resolve for PolicyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = self.policy.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let resolved: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let allowed: Vec<SocketAddr> = resolved
                .iter()
                .copied()
                .filter(|addr| policy.check_ip(addr.ip()).is_ok())
                .collect();
            if allowed.is_empty() && !resolved.is_empty() {
                return Err(Box::new(BlockedHost(host)) as _);
            }
            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}
