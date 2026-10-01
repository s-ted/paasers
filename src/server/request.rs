//! Pure request helpers: client IP, host normalization, redirects and the ACME responder.
use super::Shared;
use crate::prelude::{Resp, empty, simple};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use ipnet::IpNet;
use std::net::IpAddr;

/// TCP peer, or the right-most untrusted `X-Forwarded-For` address when the peer is a trusted proxy.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let peer = peer.to_canonical();
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|n| n.contains(ip));
    if !is_trusted(&peer) {
        return peer;
    }
    let xff = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(",");
    for part in xff.rsplit(',') {
        match part.trim().parse::<IpAddr>() {
            Ok(ip) => {
                let ip = ip.to_canonical();
                if !is_trusted(&ip) {
                    return ip;
                }
            }
            Err(_) => return peer,
        }
    }
    peer
}

/// Normalized host from `:authority` or `Host`: port stripped, lowercase, no trailing dot.
pub fn request_host(uri: &http::Uri, headers: &HeaderMap) -> Option<String> {
    let raw = match uri.host() {
        Some(h) => h.to_string(),
        None => strip_port(headers.get(header::HOST)?.to_str().ok()?).to_string(),
    };
    let h = raw.to_ascii_lowercase();
    let h = h.strip_suffix('.').unwrap_or(&h);
    let ok = !h.is_empty()
        && h.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    ok.then(|| h.to_string())
}

fn strip_port(h: &str) -> &str {
    match h.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(':') && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => h,
    }
}

pub fn https_location(host: &str, path_and_query: &str, https_port: Option<u16>) -> String {
    match https_port {
        Some(p) if p != 443 => format!("https://{host}:{p}{path_and_query}"),
        _ => format!("https://{host}{path_and_query}"),
    }
}

pub const ACME_PREFIX: &str = "/.well-known/acme-challenge/";

/// HTTP-01 responder: the key authorization for a known token, 404 otherwise.
pub fn acme_challenge(shared: &Shared, token: &str) -> Resp {
    match shared.challenges.get(token) {
        Some(ka) => simple(StatusCode::OK, "text/plain", ka),
        None => simple(StatusCode::NOT_FOUND, "text/plain", "unknown challenge"),
    }
}

pub fn redirect(location: &str) -> Resp {
    let mut r = http::Response::new(empty());
    *r.status_mut() = StatusCode::MOVED_PERMANENTLY;
    if let Ok(v) = HeaderValue::from_str(location) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xff(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        h
    }

    fn nets(s: &[&str]) -> Vec<IpNet> {
        s.iter().map(|x| x.parse().unwrap()).collect()
    }

    #[test]
    fn client_ip_ignores_xff_from_untrusted() {
        let ip = client_ip("1.2.3.4".parse().unwrap(), &xff("9.9.9.9"), &[]);
        assert_eq!(ip.to_string(), "1.2.3.4");
    }

    #[test]
    fn client_ip_uses_rightmost_untrusted_xff() {
        let t = nets(&["10.0.0.0/8"]);
        let ip = client_ip(
            "10.0.0.1".parse().unwrap(),
            &xff("6.6.6.6, 8.8.8.8, 10.0.0.2"),
            &t,
        );
        assert_eq!(ip.to_string(), "8.8.8.8");
        let ip = client_ip("10.0.0.1".parse().unwrap(), &xff("garbage"), &t);
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn client_ip_ipv4_mapped_canonical() {
        let ip = client_ip("::ffff:1.2.3.4".parse().unwrap(), &HeaderMap::new(), &[]);
        assert_eq!(ip.to_string(), "1.2.3.4");
    }

    #[test]
    fn host_from_authority_strip_port_lower_trailing_dot() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("WWW.Example.COM.:8443"));
        let uri: http::Uri = "/x".parse().unwrap();
        assert_eq!(request_host(&uri, &h).as_deref(), Some("www.example.com"));
        let uri: http::Uri = "https://Auth.Example.com:444/x".parse().unwrap();
        assert_eq!(
            request_host(&uri, &HeaderMap::new()).as_deref(),
            Some("auth.example.com")
        );
    }

    #[test]
    fn missing_or_invalid_host_is_none() {
        let uri: http::Uri = "/x".parse().unwrap();
        assert!(request_host(&uri, &HeaderMap::new()).is_none());
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("a/b{}"));
        assert!(request_host(&uri, &h).is_none());
    }

    #[test]
    fn redirect_https_preserves_path_query_and_port() {
        assert_eq!(
            https_location("a.com", "/x?y=1", Some(443)),
            "https://a.com/x?y=1"
        );
        assert_eq!(https_location("a.com", "/x", Some(8443)), "https://a.com:8443/x");
        assert_eq!(https_location("a.com", "/", None), "https://a.com/");
    }
}
