//! Cache layer tests with a fake counting backend.
use super::layer::{CacheLayer, CacheService};
use super::store::HttpCache;
use crate::config::CacheCfg;
use crate::prelude::{ClientIp, ProxyFailure, Req, Resp, RouteSvc, empty, full};
use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode, header};
use http_body_util::BodyExt;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::time::Duration;
use tower::{Layer, Service};

type Handler = Arc<dyn Fn(&Req, usize) -> Resp + Send + Sync>;

struct Fake {
    calls: Arc<AtomicUsize>,
    svc: RouteSvc,
}

fn fake(h: impl Fn(&Req, usize) -> Resp + Send + Sync + 'static) -> Fake {
    let calls = Arc::new(AtomicUsize::new(0));
    let (c, h): (_, Handler) = (calls.clone(), Arc::new(h));
    let svc = tower::service_fn(move |r: Req| {
        let n = c.fetch_add(1, SeqCst) + 1;
        let resp = h(&r, n);
        async move { Ok::<_, Infallible>(resp) }
    });
    Fake {
        calls,
        svc: RouteSvc::new(svc),
    }
}

fn cfg() -> CacheCfg {
    CacheCfg {
        max_size: 10 << 20,
        stale_while_revalidate: Duration::ZERO,
        stale_if_error: Duration::ZERO,
        default_ttl: Duration::ZERO,
        max_object_size: 1024,
    }
}

fn ok(cc: &'static str, body: &'static str) -> Resp {
    let mut r = http::Response::new(full(body));
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(cc));
    r.headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    r
}

fn req(method: Method, path: &str) -> Req {
    let mut r = http::Request::new(empty());
    *r.method_mut() = method;
    *r.uri_mut() = path.parse().unwrap();
    r.headers_mut()
        .insert(header::HOST, HeaderValue::from_static("a.test"));
    r.extensions_mut().insert(ClientIp("127.0.0.1".parse().unwrap()));
    r
}

async fn send(svc: &mut CacheService, r: Req) -> (Resp, Bytes) {
    let mut resp = svc.call(r).await.unwrap();
    let body = std::mem::replace(resp.body_mut(), empty())
        .collect()
        .await
        .unwrap()
        .to_bytes();
    (resp, body)
}

fn layered(f: &Fake, cfg: &CacheCfg) -> (CacheService, Arc<HttpCache>) {
    let cache = Arc::new(HttpCache::new(cfg));
    (CacheLayer::new(cache.clone()).layer(f.svc.clone()), cache)
}

fn xc(r: &Resp) -> &str {
    r.headers()
        .get("x-cache")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

#[tokio::test]
async fn miss_then_hit() {
    let f = fake(|_, _| ok("max-age=60", "hello"));
    let (mut svc, _) = layered(&f, &cfg());
    let (r1, b1) = send(&mut svc, req(Method::GET, "/p")).await;
    let (r2, b2) = send(&mut svc, req(Method::GET, "/p")).await;
    assert_eq!((xc(&r1), xc(&r2)), ("MISS", "HIT"));
    assert_eq!((&b1[..], &b2[..]), (&b"hello"[..], &b"hello"[..]));
    assert!(r2.headers().contains_key(header::AGE));
    assert_eq!(f.calls.load(SeqCst), 1);
    send(&mut svc, req(Method::GET, "/other")).await;
    assert_eq!(f.calls.load(SeqCst), 2);
}

#[tokio::test]
async fn head_served_from_get_entry_without_body() {
    let f = fake(|_, _| ok("max-age=60", "hello"));
    let (mut svc, _) = layered(&f, &cfg());
    send(&mut svc, req(Method::GET, "/p")).await;
    let (r, b) = send(&mut svc, req(Method::HEAD, "/p")).await;
    assert_eq!((xc(&r), b.len()), ("HIT", 0));
    assert_eq!(r.headers()[header::CONTENT_LENGTH], "5");
    assert_eq!(f.calls.load(SeqCst), 1);
}

#[tokio::test]
async fn swr_serves_stale_and_revalidates_once() {
    let c = CacheCfg {
        stale_while_revalidate: Duration::from_secs(30),
        ..cfg()
    };
    let f = fake(|_, n| {
        if n == 1 {
            ok("max-age=1", "v1")
        } else {
            ok("max-age=60", "v2")
        }
    });
    let (mut svc, cache) = layered(&f, &c);
    send(&mut svc, req(Method::GET, "/p")).await;
    // Entries age with `Instant`: simulate the passing of time through `initial_age`.
    let e = cache.get("a.test/p").unwrap();
    let mut aged = super::store::tests_support::clone_entry(&e);
    aged.initial_age = 2;
    cache.insert("a.test/p".into(), aged);
    let mut labels = Vec::new();
    for _ in 0..3 {
        let (r, b) = send(&mut svc, req(Method::GET, "/p")).await;
        labels.push((xc(&r).to_string(), b));
    }
    assert!(
        labels.iter().all(|(l, b)| l == "STALE" && &b[..] == b"v1"),
        "{labels:?}"
    );
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    assert_eq!(f.calls.load(SeqCst), 2, "exactly one revalidation");
    let (r, b) = send(&mut svc, req(Method::GET, "/p")).await;
    assert_eq!((xc(&r), &b[..]), ("HIT", &b"v2"[..]));
}

#[tokio::test]
async fn revalidation_304_refreshes() {
    let c = CacheCfg {
        stale_while_revalidate: Duration::from_secs(30),
        ..cfg()
    };
    let f = fake(|r, n| {
        if n == 1 {
            let mut x = ok("max-age=1", "body");
            x.headers_mut()
                .insert(header::ETAG, HeaderValue::from_static("\"e1\""));
            x
        } else {
            assert_eq!(r.headers().get(header::IF_NONE_MATCH).unwrap(), "\"e1\"");
            let mut x = http::Response::new(empty());
            *x.status_mut() = StatusCode::NOT_MODIFIED;
            x.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("max-age=60"));
            x
        }
    });
    let (mut svc, cache) = layered(&f, &c);
    send(&mut svc, req(Method::GET, "/p")).await;
    let e = cache.get("a.test/p").unwrap();
    let mut aged = super::store::tests_support::clone_entry(&e);
    aged.initial_age = 2;
    cache.insert("a.test/p".into(), aged);
    let (r, _) = send(&mut svc, req(Method::GET, "/p")).await;
    assert_eq!(xc(&r), "STALE");
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        if cache.get("a.test/p").is_some_and(|e| e.ttl == 60) {
            break;
        }
    }
    let e = cache.get("a.test/p").unwrap();
    assert_eq!((e.ttl, &e.body[..]), (60, &b"body"[..]));
    assert_eq!(e.headers[header::ETAG], "\"e1\"");
}

#[tokio::test]
async fn expired_entry_is_conditionally_refetched() {
    let f = fake(|r, n| {
        if n == 1 {
            let mut x = ok("max-age=1", "body");
            x.headers_mut()
                .insert(header::ETAG, HeaderValue::from_static("\"e1\""));
            x
        } else {
            assert!(r.headers().contains_key(header::IF_NONE_MATCH));
            let mut x = http::Response::new(empty());
            *x.status_mut() = StatusCode::NOT_MODIFIED;
            x.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("max-age=60"));
            x
        }
    });
    let (mut svc, cache) = layered(&f, &cfg());
    send(&mut svc, req(Method::GET, "/p")).await;
    let mut aged = super::store::tests_support::clone_entry(&cache.get("a.test/p").unwrap());
    aged.initial_age = 5;
    cache.insert("a.test/p".into(), aged);
    let (r, b) = send(&mut svc, req(Method::GET, "/p")).await;
    assert_eq!(
        (xc(&r), &b[..], r.status()),
        ("HIT", &b"body"[..], StatusCode::OK)
    );
}

#[tokio::test]
async fn stale_if_error_on_502() {
    let c = CacheCfg {
        stale_if_error: Duration::from_secs(300),
        ..cfg()
    };
    let f = fake(|_, n| {
        if n == 1 {
            ok("max-age=1", "good")
        } else {
            let mut r = http::Response::new(empty());
            *r.status_mut() = StatusCode::BAD_GATEWAY;
            r.extensions_mut().insert(ProxyFailure {
                kind: "upstream_connect",
                detail: String::new(),
                upstream: None,
            });
            r
        }
    });
    let (mut svc, cache) = layered(&f, &c);
    send(&mut svc, req(Method::GET, "/p")).await;
    let mut aged = super::store::tests_support::clone_entry(&cache.get("a.test/p").unwrap());
    aged.initial_age = 10;
    cache.insert("a.test/p".into(), aged);
    let (r, b) = send(&mut svc, req(Method::GET, "/p")).await;
    assert_eq!(
        (xc(&r), r.status(), &b[..]),
        ("STALE", StatusCode::OK, &b"good"[..])
    );
}

#[tokio::test]
async fn set_cookie_not_stored() {
    let f = fake(|_, _| {
        let mut r = ok("max-age=60", "x");
        r.headers_mut()
            .insert(header::SET_COOKIE, HeaderValue::from_static("a=b"));
        r
    });
    let (mut svc, _) = layered(&f, &cfg());
    send(&mut svc, req(Method::GET, "/p")).await;
    send(&mut svc, req(Method::GET, "/p")).await;
    assert_eq!(f.calls.load(SeqCst), 2);
}

#[tokio::test]
async fn authorization_bypass_unless_public() {
    let with_auth = |p: &str| {
        let mut r = req(Method::GET, p);
        r.headers_mut()
            .insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer t"));
        r
    };
    let f = fake(|_, _| ok("max-age=60", "x"));
    let (mut svc, _) = layered(&f, &cfg());
    send(&mut svc, with_auth("/p")).await;
    send(&mut svc, with_auth("/p")).await;
    assert_eq!(f.calls.load(SeqCst), 2, "no public/s-maxage: never stored");
    let f = fake(|_, _| ok("public, max-age=60", "x"));
    let (mut svc, _) = layered(&f, &cfg());
    send(&mut svc, with_auth("/p")).await;
    let (r, _) = send(&mut svc, with_auth("/p")).await;
    assert_eq!(xc(&r), "HIT");
    // An anonymous entry must not be served to an authenticated request.
    let f = fake(|_, _| ok("max-age=60", "x"));
    let (mut svc, _) = layered(&f, &cfg());
    send(&mut svc, req(Method::GET, "/p")).await;
    let (r, _) = send(&mut svc, with_auth("/p")).await;
    assert_ne!(xc(&r), "HIT");
}

#[tokio::test]
async fn range_bypass() {
    let f = fake(|_, _| ok("max-age=60", "x"));
    let (mut svc, _) = layered(&f, &cfg());
    let ranged = || {
        let mut r = req(Method::GET, "/p");
        r.headers_mut()
            .insert(header::RANGE, HeaderValue::from_static("bytes=0-1"));
        r
    };
    send(&mut svc, ranged()).await;
    let (r, _) = send(&mut svc, ranged()).await;
    assert_eq!((xc(&r), f.calls.load(SeqCst)), ("BYPASS", 2));
}

#[tokio::test]
async fn surrogate_key_stripped_and_purgeable() {
    let f = fake(|_, _| {
        let mut r = ok("max-age=60", "x");
        r.headers_mut()
            .insert("surrogate-key", HeaderValue::from_static("t1 t2"));
        r
    });
    let (mut svc, cache) = layered(&f, &cfg());
    let (r1, _) = send(&mut svc, req(Method::GET, "/p")).await;
    let (r2, _) = send(&mut svc, req(Method::GET, "/p")).await;
    assert!(!r1.headers().contains_key("surrogate-key") && !r2.headers().contains_key("surrogate-key"));
    assert_eq!(
        cache.purge(&super::Purge {
            tags: vec!["t2".into()],
            ..Default::default()
        }),
        1
    );
    send(&mut svc, req(Method::GET, "/p")).await;
    assert_eq!(f.calls.load(SeqCst), 2);
}

#[tokio::test]
async fn post_invalidates() {
    let f = fake(|r, _| {
        if r.method() == Method::POST {
            http::Response::new(empty())
        } else {
            ok("max-age=60", "x")
        }
    });
    let (mut svc, _) = layered(&f, &cfg());
    send(&mut svc, req(Method::GET, "/p")).await;
    send(&mut svc, req(Method::POST, "/p")).await;
    let (r, _) = send(&mut svc, req(Method::GET, "/p")).await;
    assert_eq!(xc(&r), "MISS");
}

#[tokio::test]
async fn oversized_body_not_stored() {
    // Streamed body without Content-Length, larger than max-object-size.
    let f = fake(|_, _| {
        let mut r = http::Response::new(full(vec![b'x'; 4096]));
        r.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("max-age=60"));
        r
    });
    let (mut svc, cache) = layered(&f, &cfg());
    send(&mut svc, req(Method::GET, "/p")).await;
    assert_eq!(cache.stats().entries, 0);
}

#[tokio::test]
async fn client_304_from_cache() {
    let f = fake(|_, _| {
        let mut r = ok("max-age=60", "x");
        r.headers_mut()
            .insert(header::ETAG, HeaderValue::from_static("\"abc\""));
        r
    });
    let (mut svc, _) = layered(&f, &cfg());
    send(&mut svc, req(Method::GET, "/p")).await;
    let mut r = req(Method::GET, "/p");
    r.headers_mut()
        .insert(header::IF_NONE_MATCH, HeaderValue::from_static("W/\"abc\""));
    let (resp, b) = send(&mut svc, r).await;
    assert_eq!((resp.status(), b.len()), (StatusCode::NOT_MODIFIED, 0));
    assert_eq!(resp.headers()[header::ETAG], "\"abc\"");
    assert_eq!(f.calls.load(SeqCst), 1);
}

#[tokio::test]
async fn vary_variants_do_not_mix() {
    let f = fake(|r, _| {
        let lang = r
            .headers()
            .get("accept-language")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let mut x = http::Response::new(full(lang));
        x.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("max-age=60"));
        x.headers_mut()
            .insert(header::VARY, HeaderValue::from_static("Accept-Language"));
        x
    });
    let (mut svc, _) = layered(&f, &cfg());
    let with = |l: &'static str| {
        let mut r = req(Method::GET, "/p");
        r.headers_mut()
            .insert("accept-language", HeaderValue::from_static(l));
        r
    };
    let (_, a) = send(&mut svc, with("fr")).await;
    let (_, b) = send(&mut svc, with("en")).await;
    assert_eq!((&a[..], &b[..]), (&b"fr"[..], &b"en"[..]));
}
