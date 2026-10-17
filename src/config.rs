use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;
use url::{Host, Url};

/// Methods that can be sent, and the default for `allowed_methods`.
pub const SUPPORTED_METHODS: [&str; 6] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub policy: PolicyConfig,
    pub limits: LimitsConfig,
    pub http: HttpConfig,
    pub download: DownloadConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Domains that may not be contacted. `*.example.com` blocks example.com
    /// and all of its subdomains.
    pub denied_domains: Vec<String>,
    pub allowed_schemes: Vec<String>,
    pub denied_ports: Vec<u16>,
    /// Allow loopback, private, link-local and other non-public addresses.
    pub allow_private_ips: bool,
    /// Request headers the caller may not set. A trailing `*` matches a prefix.
    pub denied_request_headers: Vec<String>,
    /// HTTP methods that may be used (`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`).
    pub allowed_methods: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            denied_domains: Vec::new(),
            allowed_schemes: vec!["http".into(), "https".into()],
            denied_ports: Vec::new(),
            allow_private_ips: false,
            denied_request_headers: [
                "host",
                "content-length",
                "transfer-encoding",
                "connection",
                "keep-alive",
                "upgrade",
                "te",
                "trailer",
                "proxy-*",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            allowed_methods: SUPPORTED_METHODS.iter().map(|m| m.to_string()).collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub max_body_bytes: usize,
    pub max_output_chars: usize,
    pub connect_timeout_secs: u64,
    pub total_timeout_secs: u64,
    pub max_redirects: usize,
    pub max_request_headers: usize,
    pub max_request_header_bytes: usize,
    pub max_request_body_bytes: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: 10_000_000,
            max_output_chars: 100_000,
            connect_timeout_secs: 5,
            total_timeout_secs: 30,
            max_redirects: 5,
            max_request_headers: 50,
            max_request_header_bytes: 8 * 1024,
            max_request_body_bytes: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    pub user_agent: String,
    /// Send every request through this proxy (`socks5://`, `socks5h://` or `http://`).
    /// Environment and system proxy settings are never used.
    pub proxy: Option<String>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            user_agent: concat!("surfshield/", env!("CARGO_PKG_VERSION")).into(),
            proxy: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DownloadConfig {
    /// Directory that MCP `save_to` paths are confined to.
    pub download_dir: PathBuf,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            download_dir: PathBuf::from("./surfshield-downloads"),
        }
    }
}

impl Config {
    /// Loads the config from `explicit` if given, otherwise from the first existing
    /// default location, otherwise falls back to built-in defaults.
    pub fn load(explicit: Option<&Path>) -> anyhow::Result<Self> {
        if let Some(path) = explicit {
            return Self::from_file(path);
        }
        for path in default_locations() {
            if path.is_file() {
                return Self::from_file(&path);
            }
        }
        Ok(Self::default())
    }

    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file {}", path.display()))?;
        let config: Config = toml::from_str(&text)
            .with_context(|| format!("invalid config file {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(proxy) = &self.http.proxy {
            validate_proxy(proxy)?;
        }
        for scheme in &self.policy.allowed_schemes {
            if !matches!(scheme.as_str(), "http" | "https") {
                bail!("unsupported scheme in allowed_schemes: {scheme:?} (only http and https)");
            }
        }
        for method in &self.policy.allowed_methods {
            if !SUPPORTED_METHODS.contains(&method.to_ascii_uppercase().as_str()) {
                bail!(
                    "unsupported method in allowed_methods: {method:?} (supported: {})",
                    SUPPORTED_METHODS.join(", ")
                );
            }
        }
        if self.limits.max_body_bytes == 0 || self.limits.max_output_chars == 0 {
            bail!("max_body_bytes and max_output_chars must be greater than 0");
        }
        if self.limits.total_timeout_secs == 0 || self.limits.connect_timeout_secs == 0 {
            bail!("timeouts must be greater than 0");
        }
        Ok(())
    }
}

/// The proxy URL itself is left out of error messages: it may contain credentials.
fn validate_proxy(proxy: &str) -> anyhow::Result<()> {
    let url = Url::parse(proxy).map_err(|e| anyhow::anyhow!("invalid proxy URL: {e}"))?;
    if !matches!(url.scheme(), "socks5" | "socks5h" | "http") {
        bail!(
            "unsupported proxy scheme {:?} (use socks5, socks5h or http)",
            url.scheme()
        );
    }
    // An IP address keeps DNS out of the picture: the proxy is reached exactly
    // where configured, even on loopback or the LAN. For non-special schemes
    // such as socks5 the url crate leaves an IPv4 address as an opaque host.
    let is_ip = match url.host() {
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => true,
        Some(Host::Domain(host)) => host.parse::<std::net::Ipv4Addr>().is_ok(),
        None => false,
    };
    if !is_ip || url.port().is_none() {
        bail!("proxy URL needs an IP address and a port, e.g. socks5h://127.0.0.1:1080");
    }
    if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
        bail!("proxy URL may not have a path, query or fragment");
    }
    Ok(())
}

fn default_locations() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("surfshield.toml")];
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(Path::new(&home).join(".config/surfshield/config.toml"));
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses() {
        let text = include_str!("../surfshield.example.toml");
        let config: Config = toml::from_str(text).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(toml::from_str::<Config>("[policy]\nallowed_domains = []").is_err());
    }

    #[test]
    fn rejects_unsupported_scheme() {
        let config: Config = toml::from_str("[policy]\nallowed_schemes = [\"ftp\"]").unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_unsupported_method() {
        let config: Config = toml::from_str("[policy]\nallowed_methods = [\"OPTIONS\"]").unwrap();
        assert!(config.validate().is_err());
        let config: Config =
            toml::from_str("[policy]\nallowed_methods = [\"get\", \"Delete\"]").unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn proxy_urls() {
        for ok in [
            "socks5://127.0.0.1:1082",
            "socks5h://127.0.0.1:1082",
            "socks5h://user:pw@[::1]:1080/",
            "http://192.168.0.10:3128",
        ] {
            assert!(validate_proxy(ok).is_ok(), "{ok} should be accepted");
        }
        for bad in [
            "127.0.0.1:1082",
            "socks4://127.0.0.1:1080",
            "https://192.168.0.10:443",
            "socks5h://127.0.0.1",
            "socks5h://localhost:1082",
            "http://proxy.example.com:3128",
            "http://192.168.0.10:3128/path",
            "not a url",
        ] {
            assert!(validate_proxy(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn proxy_in_config_file_is_validated() {
        let config: Config = toml::from_str("[http]\nproxy = \"ftp://x:21\"").unwrap();
        assert!(config.validate().is_err());
    }
}
