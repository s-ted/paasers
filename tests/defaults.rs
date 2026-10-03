//! Features that are on without configuration: security headers, rate limit, built-in MCP, private trusted proxies.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod common;
use bytes::Bytes;
use common::*;
use http_body_util::Full;
use std::net::SocketAddr;

fn kdl(backend: SocketAddr, gateway: &str, route: &str) -> String {
    format!(
        "gateway {{\n listen \"127.0.0.1:0\"\n{gateway}\n}}\nmcp-server off\nroute \"app.test\" {{\n upstream \"{backend}\"\n{route}\n}}\n"
    )
}

fn get(extra: &str) -> String {
    format!("GET / HTTP/1.1\r\nHost: app.test\r\n{extra}Connection: close\r\n\r\n")
}

async fn backend() -> SocketAddr {
    let (b, h) = spawn_backend(|_req| async move {
        http::Response::builder()
            .header("server", "nginx")
            .header("x-powered-by", "php")
            .header("x-content-type-options", "custom")
            .body(Full::new(Bytes::from("ok")))
            .unwrap()
    })
    .await;
    std::mem::forget(h);
    b
}

#[tokio::test]
async fn security_headers_by_default() {
    let b = backend().await;
    let g = spawn_gateway(&kdl(b, "", "")).await;
    let r = raw_request(g.http_addr(), &get("")).await.to_ascii_lowercase();
    assert!(!r.contains("server: nginx") && !r.contains("x-powered-by"), "{r}");
    // A value chosen by the backend is kept.
    assert!(r.contains("x-content-type-options: custom"), "{r}");
    assert!(!r.contains("strict-transport-security"), "{r}");
    g.stop().await;
    let g = spawn_gateway(&kdl(b, "", "transform off")).await;
    let r = raw_request(g.http_addr(), &get("")).await.to_ascii_lowercase();
    assert!(
        r.contains("server: nginx") && r.contains("x-powered-by: php"),
        "{r}"
    );
    g.stop().await;
}

#[tokio::test]
async fn default_rate_limit_is_high_and_can_be_lowered() {
    let b = backend().await;
    let g = spawn_gateway(&kdl(b, "", "")).await;
    for _ in 0..20 {
        let r = raw_request(g.http_addr(), &get("")).await;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    }
    g.stop().await;
    let g = spawn_gateway(&kdl(b, "", "rate-limit rps=1 burst=1")).await;
    let _ = raw_request(g.http_addr(), &get("")).await;
    let r = raw_request(g.http_addr(), &get("")).await;
    assert!(r.starts_with("HTTP/1.1 429"), "{r}");
    g.stop().await;
}

#[tokio::test]
async fn default_trusted_proxies_ignore_loopback_peers() {
    // The peer is 127.0.0.1, which is not in the private default list: X-Forwarded-For is not trusted,
    // so a client cannot dodge the limiter by forging it.
    let b = backend().await;
    let g = spawn_gateway(&kdl(b, "", "rate-limit rps=1 burst=1")).await;
    let _ = raw_request(g.http_addr(), &get("X-Forwarded-For: 1.1.1.1\r\n")).await;
    let r = raw_request(g.http_addr(), &get("X-Forwarded-For: 2.2.2.2\r\n")).await;
    assert!(r.starts_with("HTTP/1.1 429"), "{r}");
    g.stop().await;
    // Explicit opt-in for loopback makes the forwarded address count.
    let g = spawn_gateway(&kdl(
        b,
        " trusted-proxies \"127.0.0.1\"",
        "rate-limit rps=1 burst=1",
    ))
    .await;
    let _ = raw_request(g.http_addr(), &get("X-Forwarded-For: 1.1.1.1\r\n")).await;
    let r = raw_request(g.http_addr(), &get("X-Forwarded-For: 2.2.2.2\r\n")).await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    g.stop().await;
}

#[tokio::test]
async fn builtin_mcp_never_blocks_startup_when_port_is_taken() {
    let taken = tokio::net::TcpListener::bind("127.0.0.1:9090").await;
    let src = "gateway {\n listen \"127.0.0.1:0\"\n}\nroute \"a.test\" {\n upstream \"127.0.0.1:1\"\n}\n";
    let g = spawn_gateway(src).await;
    if taken.is_ok() {
        assert!(g.addrs.mcp.is_none());
    }
    g.stop().await;
}

#[tokio::test]
async fn fallback_off_leaves_proxy_failures_raw() {
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let g = spawn_gateway(&kdl(dead, "", "health-check enabled=#false")).await;
    let r = raw_request(g.http_addr(), &get("")).await.to_ascii_lowercase();
    assert!(r.contains("incident"), "page by default: {r}");
    g.stop().await;
    let g = spawn_gateway(&kdl(dead, "", "health-check enabled=#false\n fallback off")).await;
    let r = raw_request(g.http_addr(), &get("")).await.to_ascii_lowercase();
    assert!(r.starts_with("http/1.1 502") && !r.contains("maintenance"), "{r}");
    g.stop().await;
}

#[tokio::test]
async fn retry_off_does_not_try_another_backend() {
    let live = backend().await;
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let route = |extra: &str| {
        format!(
            "gateway {{\n listen \"127.0.0.1:0\"\n}}\nmcp-server off\nroute \"app.test\" {{\n upstream \"{dead}\"\n upstream \"{live}\"\n health-check enabled=#false\n rate-limit off\n{extra}\n}}\n"
        )
    };
    let g = spawn_gateway(&route("")).await;
    for _ in 0..10 {
        let r = raw_request(g.http_addr(), &get("")).await;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    }
    g.stop().await;
    let g = spawn_gateway(&route("retry off\n fallback off")).await;
    let mut failed = 0;
    for _ in 0..20 {
        if !raw_request(g.http_addr(), &get(""))
            .await
            .starts_with("HTTP/1.1 200")
        {
            failed += 1;
        }
    }
    assert!(failed > 0, "some requests must hit the dead backend");
    g.stop().await;
}
