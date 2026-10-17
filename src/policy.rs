use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use ipnet::IpNet;
use reqwest::Method;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use url::{Host, Url};

use crate::config::{LimitsConfig, PolicyConfig};
use crate::error::PolicyError;

/// Address ranges that are never reachable unless `allow_private_ips` is set.
static BLOCKED_RANGES: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        // IPv4
        "0.0.0.0/8",       // "this network"
        "10.0.0.0/8",      // private
        "100.64.0.0/10",   // carrier-grade NAT
        "127.0.0.0/8",     // loopback
        "169.254.0.0/16",  // link-local, cloud metadata
        "172.16.0.0/12",   // private
        "192.0.0.0/24",    // IETF protocol assignments
        "192.0.2.0/24",    // documentation
        "192.88.99.0/24",  // 6to4 relay anycast
        "192.168.0.0/16",  // private
        "198.18.0.0/15",   // benchmarking
        "198.51.100.0/24", // documentation
        "203.0.113.0/24",  // documentation
        "224.0.0.0/4",     // multicast
        "240.0.0.0/4",     // reserved, broadcast
        // IPv6
        "::/128",        // unspecified
        "::1/128",       // loopback
        "100::/64",      // discard
        "2001::/23",     // IETF protocol assignments (incl. Teredo)
        "2001:db8::/32", // documentation
        "fc00::/7",      // unique local
        "fe80::/10",     // link-local
        "fec0::/10",     // site-local (deprecated)
        "ff00::/8",      // multicast
    ]
    .iter()
    .map(|net| net.parse().expect("valid built-in network"))
    .collect()
});

#[derive(Debug, Clone)]
pub struct Policy {
    config: PolicyConfig,
    limits: LimitsConfig,
}

impl Policy {
    pub fn new(config: PolicyConfig, limits: LimitsConfig) -> Self {
        Self { config, limits }
    }

    pub fn allow_private_ips(&self) -> bool {
        self.config.allow_private_ips
    }

    /// Checks scheme, host, port and (for IP literals) the address itself.
    /// Hostnames are checked again after DNS resolution, see [`Policy::check_ip`].
    pub fn check_url(&self, url: &Url) -> Result<(), PolicyError> {
        let scheme = url.scheme();
        if !self.config.allowed_schemes.iter().any(|s| s == scheme) {
            return Err(PolicyError::SchemeNotAllowed(scheme.to_string()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(PolicyError::CredentialsInUrl);
        }
        let port = url
            .port_or_known_default()
            .ok_or(PolicyError::MissingHost)?;
        if self.config.denied_ports.contains(&port) {
            return Err(PolicyError::PortDenied(port));
        }
        match url.host().ok_or(PolicyError::MissingHost)? {
            Host::Domain(domain) => self.check_domain(domain),
            Host::Ipv4(ip) => self.check_ip(IpAddr::V4(ip)),
            Host::Ipv6(ip) => self.check_ip(IpAddr::V6(ip)),
        }
    }

    fn check_domain(&self, domain: &str) -> Result<(), PolicyError> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let denied = self
            .config
            .denied_domains
            .iter()
            .any(|pattern| domain_matches(&domain, pattern));
        if denied {
            return Err(PolicyError::DomainDenied(domain));
        }
        Ok(())
    }

    pub fn check_ip(&self, ip: IpAddr) -> Result<(), PolicyError> {
        if self.config.allow_private_ips || is_public_ip(ip) {
            Ok(())
        } else {
            Err(PolicyError::AddressBlocked(ip))
        }
    }

    pub fn check_method(&self, method: &Method) -> Result<(), PolicyError> {
        let allowed = self
            .config
            .allowed_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method.as_str()));
        if allowed {
            Ok(())
        } else {
            Err(PolicyError::MethodNotAllowed(method.to_string()))
        }
    }

    pub fn check_request_body(&self, body: &[u8]) -> Result<(), PolicyError> {
        let max = self.limits.max_request_body_bytes;
        if body.len() > max {
            return Err(PolicyError::RequestBodyTooLarge(max));
        }
        Ok(())
    }

    /// Validates caller-supplied request headers and turns them into a [`HeaderMap`].
    pub fn build_request_headers<'a>(
        &self,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<HeaderMap, PolicyError> {
        let mut map = HeaderMap::new();
        let mut total_bytes = 0;
        for (count, (name, value)) in headers.into_iter().enumerate() {
            if count >= self.limits.max_request_headers {
                return Err(PolicyError::TooManyHeaders(self.limits.max_request_headers));
            }
            total_bytes += name.len() + value.len();
            if total_bytes > self.limits.max_request_header_bytes {
                return Err(PolicyError::HeadersTooLarge(
                    self.limits.max_request_header_bytes,
                ));
            }
            let header_name = HeaderName::from_bytes(name.trim().as_bytes())
                .map_err(|_| PolicyError::InvalidHeaderName(name.to_string()))?;
            if self.is_header_denied(header_name.as_str()) {
                return Err(PolicyError::HeaderDenied(header_name.to_string()));
            }
            // Rejects CR, LF and other control characters (header injection).
            let header_value = HeaderValue::from_str(value.trim())
                .map_err(|_| PolicyError::InvalidHeaderValue(header_name.to_string()))?;
            map.append(header_name, header_value);
        }
        Ok(map)
    }

    fn is_header_denied(&self, name: &str) -> bool {
        self.config.denied_request_headers.iter().any(|pattern| {
            let pattern = pattern.to_ascii_lowercase();
            match pattern.strip_suffix('*') {
                Some(prefix) => name.starts_with(prefix),
                None => name == pattern,
            }
        })
    }
}

/// `example.com` matches only that domain; `*.example.com` matches example.com
/// and every subdomain of it.
fn domain_matches(domain: &str, pattern: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(base) => domain == base || domain.ends_with(&format!(".{base}")),
        None => domain == pattern,
    }
}

pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            // Addresses that embed an IPv4 address are judged by that address.
            if let Some(v4) = embedded_ipv4(v6) {
                return is_public_v4(v4);
            }
            !BLOCKED_RANGES
                .iter()
                .any(|net| net.contains(&IpAddr::V6(v6)))
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    !BLOCKED_RANGES
        .iter()
        .any(|net| net.contains(&IpAddr::V4(ip)))
}

fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let tail = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
    match s {
        // ::ffff:a.b.c.d (IPv4-mapped)
        [0, 0, 0, 0, 0, 0xffff, _, _] => Some(tail),
        // ::a.b.c.d (IPv4-compatible, deprecated) — excludes :: and ::1
        [0, 0, 0, 0, 0, 0, _, _] if s[6] != 0 => Some(tail),
        // 64:ff9b::a.b.c.d and 64:ff9b:1::/48 (NAT64)
        [0x64, 0xff9b, 0, 0, 0, 0, _, _] | [0x64, 0xff9b, 1, ..] => Some(tail),
        // 2002:aabb:ccdd::/48 (6to4)
        [0x2002, hi, lo, ..] => Some(Ipv4Addr::new(
            (hi >> 8) as u8,
            hi as u8,
            (lo >> 8) as u8,
            lo as u8,
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(f: impl FnOnce(&mut PolicyConfig)) -> Policy {
        let mut config = PolicyConfig::default();
        f(&mut config);
        Policy::new(config, LimitsConfig::default())
    }

    fn check(policy: &Policy, url: &str) -> Result<(), PolicyError> {
        policy.check_url(&Url::parse(url).unwrap())
    }

    #[test]
    fn public_urls_are_allowed_by_default() {
        let policy = policy_with(|_| {});
        assert!(check(&policy, "https://example.com/").is_ok());
        assert!(check(&policy, "http://example.com:8080/x").is_ok());
        assert!(check(&policy, "http://93.184.216.34/").is_ok());
    }

    #[test]
    fn only_http_and_https() {
        let policy = policy_with(|_| {});
        assert!(matches!(
            check(&policy, "file:///etc/passwd"),
            Err(PolicyError::SchemeNotAllowed(_))
        ));
        assert!(check(&policy, "ftp://example.com/").is_err());
    }

    #[test]
    fn https_only_when_configured() {
        let policy = policy_with(|c| c.allowed_schemes = vec!["https".into()]);
        assert!(check(&policy, "http://example.com/").is_err());
        assert!(check(&policy, "https://example.com/").is_ok());
    }

    #[test]
    fn denylist_exact_and_wildcard() {
        let policy = policy_with(|c| {
            c.denied_domains = vec!["evil.com".into(), "*.corp.example".into()];
        });
        assert!(check(&policy, "https://evil.com/").is_err());
        assert!(check(&policy, "https://EVIL.com./").is_err());
        assert!(check(&policy, "https://sub.evil.com/").is_ok());
        assert!(check(&policy, "https://notevil.com/").is_ok());
        assert!(check(&policy, "https://corp.example/").is_err());
        assert!(check(&policy, "https://a.b.corp.example/").is_err());
        assert!(check(&policy, "https://xcorp.example/").is_ok());
    }

    #[test]
    fn denied_ports() {
        let policy = policy_with(|c| c.denied_ports = vec![22, 443]);
        assert!(check(&policy, "https://example.com/").is_err());
        assert!(check(&policy, "http://example.com:22/").is_err());
        assert!(check(&policy, "http://example.com/").is_ok());
    }

    #[test]
    fn credentials_in_url_rejected() {
        let policy = policy_with(|_| {});
        assert!(check(&policy, "https://user:pw@example.com/").is_err());
    }

    #[test]
    fn private_ip_literals_blocked() {
        let policy = policy_with(|_| {});
        for url in [
            "http://127.0.0.1/",
            "http://127.1/", // shorthand for 127.0.0.1
            "http://10.1.2.3/",
            "http://169.254.169.254/latest/meta-data/",
            "http://192.168.1.1/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[fd00::1]/",
            "http://[fe80::1]/",
            "http://2130706433/", // 127.0.0.1 as integer
        ] {
            assert!(
                matches!(check(&policy, url), Err(PolicyError::AddressBlocked(_))),
                "{url} should be blocked"
            );
        }
    }

    #[test]
    fn private_ips_allowed_when_configured() {
        let policy = policy_with(|c| c.allow_private_ips = true);
        assert!(check(&policy, "http://127.0.0.1:8080/").is_ok());
    }

    #[test]
    fn embedded_ipv4_is_checked() {
        assert!(!is_public_ip("64:ff9b::7f00:1".parse().unwrap()));
        assert!(!is_public_ip("2002:7f00:1::".parse().unwrap()));
        assert!(!is_public_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_public_ip("::ffff:8.8.8.8".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn headers_are_validated() {
        let policy = policy_with(|_| {});
        let ok = policy
            .build_request_headers([("Accept", "text/html"), ("Authorization", "Bearer x")])
            .unwrap();
        assert_eq!(ok.len(), 2);

        for name in [
            "Host",
            "content-length",
            "Proxy-Authorization",
            "Transfer-Encoding",
        ] {
            assert!(
                matches!(
                    policy.build_request_headers([(name, "x")]),
                    Err(PolicyError::HeaderDenied(_))
                ),
                "{name} should be denied"
            );
        }
        assert!(matches!(
            policy.build_request_headers([("X-Test", "a\r\nInjected: yes")]),
            Err(PolicyError::InvalidHeaderValue(_))
        ));
        assert!(matches!(
            policy.build_request_headers([("Bad Name", "x")]),
            Err(PolicyError::InvalidHeaderName(_))
        ));
    }

    #[test]
    fn header_limits() {
        let policy = policy_with(|_| {});
        let many: Vec<(String, String)> =
            (0..51).map(|i| (format!("x-h{i}"), "v".into())).collect();
        assert!(matches!(
            policy.build_request_headers(many.iter().map(|(k, v)| (k.as_str(), v.as_str()))),
            Err(PolicyError::TooManyHeaders(_))
        ));
        let big = "v".repeat(9000);
        assert!(matches!(
            policy.build_request_headers([("x-big", big.as_str())]),
            Err(PolicyError::HeadersTooLarge(_))
        ));
    }

    #[test]
    fn methods_and_request_body() {
        let policy = policy_with(|c| c.allowed_methods = vec!["get".into(), "HEAD".into()]);
        assert!(policy.check_method(&Method::GET).is_ok());
        assert!(matches!(
            policy.check_method(&Method::POST),
            Err(PolicyError::MethodNotAllowed(_))
        ));
        assert!(policy_with(|_| {}).check_method(&Method::POST).is_ok());

        let limits = LimitsConfig {
            max_request_body_bytes: 4,
            ..Default::default()
        };
        let policy = Policy::new(PolicyConfig::default(), limits);
        assert!(policy.check_request_body(b"1234").is_ok());
        assert!(matches!(
            policy.check_request_body(b"12345"),
            Err(PolicyError::RequestBodyTooLarge(4))
        ));
    }
}
