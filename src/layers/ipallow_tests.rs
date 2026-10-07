//! `allow-ips` matcher and layer (plans/15 §4).
use super::ipallow::*;
use crate::prelude::{ClientIp, IncidentKind, Req, Resp, RouteSvc, empty};
use ipnet::IpNet;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::{Layer, Service};

fn nets(v: &[&str]) -> Vec<IpNet> {
    IpNet::aggregate(
        &v.iter()
            .map(|s| crate::config::units::parse_net(s).unwrap())
            .collect(),
    )
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn matcher_v4_v6_edges() {
    let m = IpAllow::from_nets(&nets(&["10.0.0.0/24", "192.0.2.7", "2001:db8::/32", "::1"]));
    for ok in [
        "10.0.0.0",
        "10.0.0.255",
        "192.0.2.7",
        "2001:db8::",
        "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
        "::1",
    ] {
        assert!(m.contains(ip(ok)), "{ok}");
    }
    for ko in [
        "9.255.255.255",
        "10.0.1.0",
        "192.0.2.6",
        "192.0.2.8",
        "2001:db7:ffff::",
        "2001:db9::",
        "::2",
        "0.0.0.0",
        "::",
    ] {
        assert!(!m.contains(ip(ko)), "{ko}");
    }
    // Families do not leak into each other.
    assert!(!IpAllow::from_nets(&nets(&["0.0.0.0/0"])).contains(ip("2001:db8::1")));
    assert!(!IpAllow::from_nets(&nets(&["::/0"])).contains(ip("10.0.0.1")));
}

#[test]
fn matcher_ipv4_mapped() {
    let m = IpAllow::from_nets(&nets(&["192.0.2.0/24"]));
    assert!(m.contains(ip("::ffff:192.0.2.10")));
    assert!(!m.contains(ip("::ffff:198.51.100.1")));
}

/// Deterministic xorshift, enough to spread test ranges.
fn rng(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

#[test]
fn matcher_many_ranges() {
    let mut s = 0x9E37_79B9_7F4A_7C15_u64;
    let raw: Vec<IpNet> = (0..10_000)
        .map(|_| {
            let r = rng(&mut s);
            let len = 8 + (r % 25) as u8;
            let addr = std::net::Ipv4Addr::from((r >> 32) as u32);
            ipnet::Ipv4Net::new(addr, len).unwrap().trunc().into()
        })
        .collect();
    let m = IpAllow::from_nets(&IpNet::aggregate(&raw));
    for _ in 0..20_000 {
        let a = IpAddr::from(std::net::Ipv4Addr::from(rng(&mut s) as u32));
        assert_eq!(m.contains(a), raw.iter().any(|n| n.contains(&a)), "{a}");
    }
}

fn svc(allowed: &[&str], hits: Arc<AtomicUsize>) -> RouteSvc {
    let inner = RouteSvc::new(tower::service_fn(move |_r: Req| {
        hits.fetch_add(1, Ordering::SeqCst);
        async { Ok::<Resp, Infallible>(http::Response::new(empty())) }
    }));
    RouteSvc::new(IpAllowLayer::new(&nets(allowed)).layer(inner))
}

fn req(client: Option<&str>) -> Req {
    let mut r = http::Request::new(empty());
    if let Some(c) = client {
        r.extensions_mut().insert(ClientIp(ip(c)));
    }
    r
}

#[tokio::test]
async fn allowed_passes() {
    let hits = Arc::new(AtomicUsize::new(0));
    let mut s = svc(&["192.0.2.0/24"], hits.clone());
    assert_eq!(s.call(req(Some("192.0.2.1"))).await.unwrap().status(), 200);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn refused_403_ip_blocked() {
    let hits = Arc::new(AtomicUsize::new(0));
    let mut s = svc(&["192.0.2.0/24"], hits.clone());
    let r = s.call(req(Some("198.51.100.1"))).await.unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(r.extensions().get::<IncidentKind>().unwrap().0, "ip_blocked");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "backend never reached");
}

#[tokio::test]
async fn missing_client_ip_refused() {
    let hits = Arc::new(AtomicUsize::new(0));
    let mut s = svc(&["0.0.0.0/0", "::/0"], hits.clone());
    assert_eq!(s.call(req(None)).await.unwrap().status(), 403);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}
