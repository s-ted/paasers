//! Request and response header rewriting for the upstream hop (pure functions).
use crate::observe::trace;
use crate::prelude::TraceCtx;
use http::header::{CONNECTION, EXPECT, HOST, UPGRADE, VIA};
use http::{HeaderMap, HeaderName, HeaderValue};
use std::net::IpAddr;

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

pub struct ReqCtx<'a> {
    pub peer_ip: IpAddr,
    pub peer_trusted: bool,
    pub client_ip: IpAddr,
    pub scheme: &'static str,
    /// Original host (with port if any), used when the request has no `Host` header (h2).
    pub host: &'a str,
    pub trace: &'a TraceCtx,
    pub is_upgrade: bool,
}

fn connection_tokens(h: &HeaderMap) -> impl Iterator<Item = &str> {
    h.get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// `Connection: upgrade` together with an `Upgrade` header.
pub fn is_upgrade(h: &HeaderMap) -> bool {
    h.contains_key(UPGRADE) && connection_tokens(h).any(|t| t.eq_ignore_ascii_case("upgrade"))
}

fn strip_hop_by_hop(h: &mut HeaderMap) {
    let listed: Vec<HeaderName> = connection_tokens(h)
        .filter_map(|t| HeaderName::from_bytes(t.as_bytes()).ok())
        .collect();
    HOP_BY_HOP.iter().for_each(|n| {
        h.remove(*n);
    });
    listed.iter().for_each(|n| {
        h.remove(n);
    });
}

fn set(h: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        h.insert(HeaderName::from_static(name), v);
    }
}

pub fn prepare_request(h: &mut HeaderMap, ctx: &ReqCtx<'_>) {
    let upgrade = if ctx.is_upgrade {
        h.get(UPGRADE).cloned()
    } else {
        None
    };
    strip_hop_by_hop(h);
    h.remove(EXPECT);
    if let Some(u) = upgrade {
        h.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        h.insert(UPGRADE, u);
    }
    if !h.contains_key(HOST) {
        set_host(h, ctx.host);
    }
    let peer = ctx.peer_ip.to_string();
    let xff = if ctx.peer_trusted {
        let prev = h
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ");
        if prev.is_empty() {
            peer
        } else {
            format!("{prev}, {peer}")
        }
    } else {
        peer
    };
    h.remove("x-forwarded-for");
    set(h, "x-forwarded-for", &xff);
    set(h, "x-real-ip", &ctx.client_ip.to_string());
    set(h, "x-forwarded-proto", ctx.scheme);
    set(h, "x-forwarded-host", ctx.host);
    h.append(VIA, HeaderValue::from_static("1.1 paasers"));
    set(h, "traceparent", &trace::traceparent(ctx.trace));
    set(h, "x-request-id", &trace::trace_hex(ctx.trace.trace_id));
}

fn set_host(h: &mut HeaderMap, host: &str) {
    if let Ok(v) = HeaderValue::from_str(host) {
        h.insert(HOST, v);
    }
}

pub fn prepare_response(h: &mut HeaderMap, switching_protocols: bool) {
    if switching_protocols {
        return;
    }
    strip_hop_by_hop(h);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> TraceCtx {
        TraceCtx {
            trace_id: 0xabc,
            parent_span: None,
            span_id: 0x42,
            sampled: true,
        }
    }

    fn ctx<'a>(t: &'a TraceCtx, trusted: bool, upgrade: bool) -> ReqCtx<'a> {
        ReqCtx {
            peer_ip: "10.0.0.9".parse().unwrap(),
            peer_trusted: trusted,
            client_ip: "1.2.3.4".parse().unwrap(),
            scheme: "https",
            host: "example.com:8443",
            trace: t,
            is_upgrade: upgrade,
        }
    }

    fn map(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        pairs.iter().for_each(|(k, v)| {
            h.append(HeaderName::from_static(k), HeaderValue::from_static(v));
        });
        h
    }

    #[test]
    fn strips_hop_by_hop_and_connection_listed() {
        let mut h = map(&[
            ("connection", "keep-alive, x-secret"),
            ("x-secret", "1"),
            ("te", "trailers"),
            ("transfer-encoding", "chunked"),
            ("expect", "100-continue"),
            ("x-keep", "1"),
        ]);
        let t = trace();
        prepare_request(&mut h, &ctx(&t, false, false));
        for gone in ["connection", "x-secret", "te", "transfer-encoding", "expect"] {
            assert!(!h.contains_key(gone), "{gone}");
        }
        assert!(h.contains_key("x-keep"));
    }

    #[test]
    fn xff_appends_trusted_resets_untrusted() {
        let t = trace();
        let mut h = map(&[("x-forwarded-for", "8.8.8.8")]);
        prepare_request(&mut h, &ctx(&t, true, false));
        assert_eq!(h["x-forwarded-for"], "8.8.8.8, 10.0.0.9");
        let mut h = map(&[("x-forwarded-for", "6.6.6.6")]);
        prepare_request(&mut h, &ctx(&t, false, false));
        assert_eq!(h["x-forwarded-for"], "10.0.0.9");
        assert_eq!(h["x-real-ip"], "1.2.3.4");
        assert_eq!(h["x-forwarded-proto"], "https");
        assert_eq!(h["x-forwarded-host"], "example.com:8443");
    }

    #[test]
    fn h2_request_gets_host_header() {
        let t = trace();
        let mut h = HeaderMap::new();
        prepare_request(&mut h, &ctx(&t, false, false));
        assert_eq!(h[HOST], "example.com:8443");
        let mut h = map(&[("host", "orig.com")]);
        prepare_request(&mut h, &ctx(&t, false, false));
        assert_eq!(h[HOST], "orig.com");
    }

    #[test]
    fn upgrade_keeps_connection_upgrade() {
        let t = trace();
        let mut h = map(&[("connection", "Upgrade"), ("upgrade", "websocket")]);
        assert!(is_upgrade(&h));
        prepare_request(&mut h, &ctx(&t, false, true));
        assert_eq!(h[CONNECTION], "upgrade");
        assert_eq!(h[UPGRADE], "websocket");
        assert!(!is_upgrade(&map(&[("upgrade", "websocket")])));
    }

    #[test]
    fn via_appended() {
        let t = trace();
        let mut h = map(&[("via", "1.1 other")]);
        prepare_request(&mut h, &ctx(&t, false, false));
        let v: Vec<_> = h
            .get_all(VIA)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(v, vec!["1.1 other", "1.1 paasers"]);
    }

    #[test]
    fn request_id_overwritten_and_traceparent_set() {
        let t = trace();
        let mut h = map(&[("x-request-id", "evil")]);
        prepare_request(&mut h, &ctx(&t, false, false));
        assert_eq!(h["x-request-id"], "00000000000000000000000000000abc");
        assert_eq!(
            h["traceparent"],
            "00-00000000000000000000000000000abc-0000000000000042-01"
        );
    }

    #[test]
    fn response_hop_by_hop_removed_except_101() {
        let mut h = map(&[("connection", "close"), ("keep-alive", "x"), ("x-keep", "1")]);
        prepare_response(&mut h, false);
        assert!(!h.contains_key("connection") && h.contains_key("x-keep"));
        let mut h = map(&[("connection", "upgrade"), ("upgrade", "websocket")]);
        prepare_response(&mut h, true);
        assert!(h.contains_key("connection") && h.contains_key("upgrade"));
    }
}
