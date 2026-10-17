use std::net::IpAddr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("scheme {0:?} is not allowed")]
    SchemeNotAllowed(String),
    #[error("URL has no host")]
    MissingHost,
    #[error("credentials in the URL are not allowed; use an Authorization header instead")]
    CredentialsInUrl,
    #[error("port {0} is denied by policy")]
    PortDenied(u16),
    #[error("domain {0} is denied by policy")]
    DomainDenied(String),
    #[error("address {0} is not a public address and is blocked by policy")]
    AddressBlocked(IpAddr),
    #[error("{0} resolves only to blocked (non-public) addresses")]
    AllAddressesBlocked(String),
    #[error("request header {0:?} may not be set")]
    HeaderDenied(String),
    #[error("invalid request header name {0:?}")]
    InvalidHeaderName(String),
    #[error("invalid value for request header {0:?}")]
    InvalidHeaderValue(String),
    #[error("too many request headers (max {0})")]
    TooManyHeaders(usize),
    #[error("request headers too large (max {0} bytes)")]
    HeadersTooLarge(usize),
    #[error("method {0} is not allowed")]
    MethodNotAllowed(String),
    #[error("request body too large (max {0} bytes)")]
    RequestBodyTooLarge(usize),
}

// The wrapped errors are part of the message rather than a `source`, so
// error-chain printers (`{:#}`) do not repeat them.
#[derive(Debug, Error)]
pub enum FetchError {
    #[error("invalid URL: {0}")]
    InvalidUrl(url::ParseError),
    #[error("blocked: {0}")]
    Policy(PolicyError),
    #[error("request timed out after {0} seconds")]
    Timeout(u64),
    #[error("too many redirects (max {0})")]
    TooManyRedirects(usize),
    #[error("redirect without a valid Location header")]
    InvalidRedirect,
    #[error(
        "the server redirected the {method} request to another origin ({url}); not repeated. \
         Send the request to that URL directly if it is intended"
    )]
    CrossOriginRedirect { method: String, url: String },
    #[error("HTTP error: {0}")]
    Http(String),
}

#[derive(Debug, Error)]
pub enum SaveError {
    #[error("save_to must be a relative path inside the download directory")]
    PathOutsideDownloadDir,
    #[error("file {0} already exists; set overwrite to replace it")]
    AlreadyExists(String),
    #[error("response body exceeded max_body_bytes ({0}); refusing to save an incomplete file")]
    BodyTruncated(usize),
    #[error("I/O error: {0}")]
    Io(std::io::Error),
}

impl From<std::io::Error> for SaveError {
    fn from(err: std::io::Error) -> Self {
        SaveError::Io(err)
    }
}

impl From<url::ParseError> for FetchError {
    fn from(err: url::ParseError) -> Self {
        FetchError::InvalidUrl(err)
    }
}

impl From<PolicyError> for FetchError {
    fn from(err: PolicyError) -> Self {
        FetchError::Policy(err)
    }
}

impl FetchError {
    /// Turns a reqwest error into a [`FetchError`], surfacing policy violations raised
    /// inside the DNS resolver instead of a generic connect error.
    pub fn from_reqwest(err: reqwest::Error) -> Self {
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&err);
        while let Some(e) = source {
            if let Some(blocked) = e.downcast_ref::<BlockedHost>() {
                return FetchError::Policy(PolicyError::AllAddressesBlocked(blocked.0.clone()));
            }
            source = e.source();
        }
        FetchError::Http(error_chain(&err))
    }
}

/// Error returned by the policy-enforcing DNS resolver.
#[derive(Debug, Error)]
#[error("{0} resolves only to blocked addresses")]
pub struct BlockedHost(pub String);

fn error_chain(err: &dyn std::error::Error) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(e) = source {
        let text = e.to_string();
        if !message.contains(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        source = e.source();
    }
    message
}
