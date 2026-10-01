//! Integration tests for the HTTP cache through the full gateway (P8). The cache + compression
//! combination from plans/08 §7 is covered in P10, once the compression layer exists.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod common;
use bytes::Bytes;
use common::*;
use http_body_util::Full;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

fn kdl(backend: std::net::SocketAddr, cache: &str) -> String {
    format!(
        "gateway {{\n listen \"127.0.0.1:0\"\n}}\nroute \"app.test\" {{\n upstream \"{backend}\"\n {cache}\n}}\n"
    )
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
}

/// The entry is stored when the streamed body completes, slightly after the client has the response.
async fn wait_for_entries(g: &GatewayHandle, n: usize) -> bool {
    for _ in 0..100 {
        if g.shared
            .caches
            .get("app.test")
            .is_some_and(|c| c.stats().entries >= n)
        {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    false
}

async fn counting_backend() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let (addr, _h) = spawn_backend(move |_| {
        let n = n2.clone();
        async move {
            n.fetch_add(1, SeqCst);
            http::Response::builder()
                .header("cache-control", "max-age=60")
                .header("surrogate-key", "page home")
                .body(Full::new(Bytes::from_static(b"cached body")))
                .unwrap()
        }
    })
    .await;
    std::mem::forget(_h);
    (addr, n)
}

#[tokio::test]
async fn second_request_is_a_hit_and_backend_called_once() {
    let (b, calls) = counting_backend().await;
    let g = spawn_gateway(&kdl(b, "cache max-size=\"10MiB\"")).await;
    let r1 = raw_request(g.http_addr(), &get("/a")).await.to_ascii_lowercase();
    assert!(wait_for_entries(&g, 1).await, "entry never stored");
    let r2 = raw_request(g.http_addr(), &get("/a")).await.to_ascii_lowercase();
    assert!(r1.contains("x-cache: miss"), "{r1}");
    assert!(
        r2.contains("x-cache: hit") && r2.contains("age: ") && r2.ends_with("cached body"),
        "{r2}"
    );
    assert!(!r1.contains("surrogate-key") && !r2.contains("surrogate-key"));
    assert_eq!(calls.load(SeqCst), 1);
    g.stop().await;
}

#[tokio::test]
async fn purge_by_tag_forces_a_miss() {
    let (b, calls) = counting_backend().await;
    let g = spawn_gateway(&kdl(b, "cache")).await;
    raw_request(g.http_addr(), &get("/a")).await;
    assert!(wait_for_entries(&g, 1).await, "entry never stored");
    let cache = g.shared.caches.get("app.test").unwrap();
    assert_eq!(
        cache.purge(&paasers::cache::Purge {
            tags: vec!["page".into()],
            ..Default::default()
        }),
        1
    );
    let r = raw_request(g.http_addr(), &get("/a")).await.to_ascii_lowercase();
    assert!(r.contains("x-cache: miss"), "{r}");
    assert_eq!(calls.load(SeqCst), 2);
    g.stop().await;
}

#[tokio::test]
async fn route_without_cache_has_no_x_cache_header() {
    let (b, calls) = counting_backend().await;
    let g = spawn_gateway(&kdl(b, "")).await;
    let r = raw_request(g.http_addr(), &get("/a")).await.to_ascii_lowercase();
    assert!(!r.contains("x-cache"), "{r}");
    raw_request(g.http_addr(), &get("/a")).await;
    assert_eq!(calls.load(SeqCst), 2);
    g.stop().await;
}
