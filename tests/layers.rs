//! Security layers through the full gateway (P10), and cache + compression (P8 §7).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod common;
use bytes::Bytes;
use common::*;
use http_body_util::Full;

const GEO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/GeoIP2-Country-Test.mmdb"
);

fn kdl(backend: std::net::SocketAddr, body: &str) -> String {
    format!(
        "gateway {{\n listen \"127.0.0.1:0\"\n trusted-proxies \"127.0.0.1\"\n}}\nroute \"app.test\" {{\n upstream \"{backend}\"\n{body}\n}}\n"
    )
}

fn get(path: &str, extra: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: app.test\r\n{extra}Connection: close\r\n\r\n")
}

async fn text_backend() -> std::net::SocketAddr {
    let (b, h) = spawn_backend(|req| async move {
        let mut r = http::Response::builder()
            .header("cache-control", "max-age=60")
            .header("content-type", "text/plain");
        for n in ["x-country-code", "x-user-id", "x-api-key-name"] {
            if let Some(v) = req.headers().get(n) {
                r = r.header(format!("x-seen-{n}"), v.clone());
            }
        }
        r.body(Full::new(Bytes::from("compress me please ".repeat(200))))
            .unwrap()
    })
    .await;
    std::mem::forget(h);
    b
}

#[tokio::test]
async fn cache_hit_is_compressed_with_zstd() {
    let b = text_backend().await;
    let g = spawn_gateway(&kdl(b, " cache\n compression")).await;
    let first = raw_request(g.http_addr(), &get("/a", "Accept-Encoding: gzip\r\n"))
        .await
        .to_ascii_lowercase();
    assert!(
        first.contains("x-cache: miss") && first.contains("content-encoding: gzip"),
        "{first}"
    );
    for _ in 0..100 {
        if g.shared
            .caches
            .get("app.test")
            .is_some_and(|c| c.stats().entries >= 1)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let second = raw_request(g.http_addr(), &get("/a", "Accept-Encoding: zstd\r\n"))
        .await
        .to_ascii_lowercase();
    assert!(second.contains("x-cache: hit"), "{second}");
    assert!(
        second.contains("content-encoding: zstd"),
        "compression sits above the cache: {second}"
    );
    g.stop().await;
}

#[tokio::test]
async fn geoip_blocks_by_forwarded_ip_from_trusted_proxy() {
    let b = text_backend().await;
    let g = spawn_gateway(&kdl(
        b,
        &format!(" geoip database=\"{GEO}\" block-countries=\"GB\""),
    ))
    .await;
    let blocked = raw_request(g.http_addr(), &get("/", "X-Forwarded-For: 81.2.69.160\r\n")).await;
    assert!(blocked.starts_with("HTTP/1.1 403"), "{blocked}");
    let ok = raw_request(g.http_addr(), &get("/", "X-Forwarded-For: 10.1.1.1\r\n"))
        .await
        .to_ascii_lowercase();
    assert!(
        ok.starts_with("http/1.1 200") && ok.contains("x-seen-x-country-code: xx"),
        "{ok}"
    );
    assert!(
        g.shared
            .recorder
            .query(&Default::default())
            .iter()
            .any(|i| i.kind == "geo_blocked")
    );
    g.stop().await;
}

#[tokio::test]
async fn rate_limit_returns_429_with_retry_after() {
    let b = text_backend().await;
    let g = spawn_gateway(&kdl(b, " rate-limit rps=1 burst=2")).await;
    for _ in 0..2 {
        assert!(
            raw_request(g.http_addr(), &get("/", ""))
                .await
                .starts_with("HTTP/1.1 200")
        );
    }
    let r = raw_request(g.http_addr(), &get("/", "")).await;
    assert!(
        r.starts_with("HTTP/1.1 429") && r.to_ascii_lowercase().contains("retry-after: "),
        "{r}"
    );
    g.stop().await;
}

#[tokio::test]
async fn api_key_or_jwt_with_exemption_and_anti_spoofing() {
    let b = text_backend().await;
    let key_hash = "47bd0e2f856fe258ebba4d00930ab811d0c004dafae068c9d72511ca3512cca6";
    let src = kdl(
        b,
        &format!(
            " api-keys {{\n key \"{key_hash}\" name=\"ci\"\n }}\n jwt-validation {{\n secret-env \"JWT_SECRET_KEY\"\n }}"
        ),
    );
    let mut cfg =
        paasers::config::parse_str(&src, &|_| Some("test-secret-at-least-32-bytes-long!!".into())).unwrap();
    cfg.gateway.storage_path = tempfile::tempdir().unwrap().keep().join("c.db");
    let (tx, rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(paasers::server::run_with(cfg, None, tx, shutdown.clone()));
    let addr = rx.await.unwrap().http;
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], addr.port()));
    let ok = raw_request(
        addr,
        &get("/", "X-Api-Key: test-api-key-0123456789\r\nX-User-Id: forged\r\n"),
    )
    .await
    .to_ascii_lowercase();
    assert!(
        ok.starts_with("http/1.1 200") && ok.contains("x-seen-x-api-key-name: ci"),
        "{ok}"
    );
    assert!(
        !ok.contains("forged"),
        "spoofed identity header must never reach the backend: {ok}"
    );
    assert!(
        raw_request(addr, &get("/", "X-Api-Key: wrong\r\n"))
            .await
            .starts_with("HTTP/1.1 401")
    );
    let none = raw_request(addr, &get("/", "")).await;
    assert!(
        none.starts_with("HTTP/1.1 401") && none.contains("token_required"),
        "{none}"
    );
    shutdown.cancel();
    let _ = task.await;
}
