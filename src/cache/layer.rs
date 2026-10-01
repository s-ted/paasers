//! `CacheLayer`: serves, stores and revalidates responses (see plans/08).
use super::key::{primary, vary_matches};
use super::policy::{Ctx, storable};
use super::respond::{
    Origin, add_validators, build_entry, from_entry, invalidate, merge_304, storable_headers,
};
use super::revalidate::{Snapshot, revalidate};
use super::store::{HttpCache, State};
use super::tee::TeeBody;
use crate::prelude::{BoxFut, ProxyFailure, Req, Resp, RouteSvc, boxed};
use crate::proxy::headers::is_upgrade;
use crate::server::request::request_host;
use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode, header};
use http_body::Body as _;
use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::Service;

#[derive(Clone)]
pub struct CacheLayer {
    cache: Arc<HttpCache>,
}

impl CacheLayer {
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }
}

impl tower::Layer<RouteSvc> for CacheLayer {
    type Service = CacheService;
    fn layer(&self, inner: RouteSvc) -> CacheService {
        CacheService {
            inner,
            cache: self.cache.clone(),
        }
    }
}

#[derive(Clone)]
pub struct CacheService {
    inner: RouteSvc,
    cache: Arc<HttpCache>,
}

/// Concrete call helper (rule R5).
pub async fn call_svc(svc: &mut RouteSvc, req: Req) -> Resp {
    let ready = std::future::poll_fn(|cx| svc.poll_ready(cx)).await;
    let fut = match ready {
        Ok(()) => svc.call(req),
        Err(e) => match e {},
    };
    match fut.await {
        Ok(r) => r,
        Err(e) => match e {},
    }
}

fn finish(mut resp: Resp, cache: &HttpCache, label: &'static str) -> Resp {
    resp.headers_mut().remove("surrogate-key");
    if !resp.headers().contains_key("x-cache") {
        resp.headers_mut()
            .insert("x-cache", HeaderValue::from_static(label));
        resp.extensions_mut().insert(crate::prelude::CacheStatus(label));
    }
    cache.count(label);
    resp
}

async fn handle(cache: Arc<HttpCache>, mut inner: RouteSvc, mut req: Req) -> Resp {
    let method = req.method().clone();
    let host = request_host(req.uri(), req.headers()).unwrap_or_default();
    let key = primary(&host, req.uri());
    let cacheable = matches!(method, Method::GET | Method::HEAD)
        && !req.headers().contains_key(header::RANGE)
        && !is_upgrade(req.headers());
    if !cacheable {
        let unsafe_method = matches!(
            method,
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        );
        let resp = call_svc(&mut inner, req).await;
        if unsafe_method {
            invalidate(&cache, &host, &key, &resp);
        }
        return finish(resp, &cache, "BYPASS");
    }
    let head = method == Method::HEAD;
    let req_headers = req.headers().clone();
    let sensitive =
        req_headers.contains_key(header::AUTHORIZATION) || req_headers.contains_key(header::COOKIE);
    let entry = cache
        .get(&key)
        .filter(|e| vary_matches(&e.vary, &req_headers) && (!sensitive || e.auth_ok));
    if let Some(e) = &entry {
        match e.state() {
            State::Fresh => return finish(from_entry(e, &req_headers, head, "HIT"), &cache, "HIT"),
            State::StaleSwr => {
                if cache.begin_revalidation(&key) {
                    let snap = Snapshot::capture(&req);
                    tokio::spawn(revalidate(
                        cache.clone(),
                        key.clone(),
                        inner.clone(),
                        snap,
                        e.clone(),
                    ));
                }
                return finish(from_entry(e, &req_headers, head, "STALE"), &cache, "STALE");
            }
            State::StaleSie | State::Expired => {}
        }
    }
    let client_conditional = req_headers.contains_key(header::IF_NONE_MATCH)
        || req_headers.contains_key(header::IF_MODIFIED_SINCE);
    let added = match &entry {
        Some(e) if !client_conditional => add_validators(req.headers_mut(), &e.headers),
        _ => false,
    };
    let resp = call_svc(&mut inner, req).await;
    let failed = resp.status().as_u16() >= 500 || resp.extensions().get::<ProxyFailure>().is_some();
    if let Some(e) = &entry {
        if added && resp.status() == StatusCode::NOT_MODIFIED {
            let merged = merge_304(&e.headers, resp.headers());
            let ctx = Ctx {
                is_get: true,
                sensitive: e.auth_ok,
                has_proxy_failure: false,
            };
            let f = storable(e.status, &merged, &ctx, &cache.cfg);
            let o = Origin {
                host: &e.host,
                path: &e.path,
                req_headers: &req_headers,
            };
            let fresh = f.map(|f| build_entry(e.status, &merged, e.body.clone(), &f, &o));
            let served = fresh.as_ref().map_or_else(
                || from_entry(e, &req_headers, head, "HIT"),
                |n| from_entry(n, &req_headers, head, "HIT"),
            );
            if let Some(n) = fresh {
                cache.insert(key, n);
            }
            return finish(served, &cache, "HIT");
        }
        if failed && e.age() < e.ttl + e.sie {
            return finish(from_entry(e, &req_headers, head, "STALE"), &cache, "STALE");
        }
    }
    store_or_pass(
        &cache,
        key,
        resp,
        &req_headers,
        &host,
        entry.is_some(),
        method == Method::GET,
        sensitive,
    )
}

#[allow(clippy::too_many_arguments)]
fn store_or_pass(
    cache: &Arc<HttpCache>,
    key: String,
    resp: Resp,
    req_headers: &http::HeaderMap,
    host: &str,
    had_entry: bool,
    is_get: bool,
    sensitive: bool,
) -> Resp {
    let ctx = Ctx {
        is_get,
        sensitive,
        has_proxy_failure: resp.extensions().get::<ProxyFailure>().is_some(),
    };
    let Some(f) = storable(resp.status(), resp.headers(), &ctx, &cache.cfg) else {
        if had_entry && resp.status().as_u16() < 500 && resp.status() != StatusCode::NOT_MODIFIED {
            cache.remove(&key);
        }
        return finish(resp, cache, "MISS");
    };
    let path = key.strip_prefix(host).unwrap_or("/").to_string();
    let (parts, body) = resp.into_parts();
    let headers = storable_headers(&parts.headers);
    let (status, rh, req_h, host) = (
        parts.status,
        parts.headers.clone(),
        req_headers.clone(),
        host.to_string(),
    );
    let make = move |bytes: Bytes| {
        let o = Origin {
            host: &host,
            path: &path,
            req_headers: &req_h,
        };
        build_entry(status, &rh, bytes, &f, &o)
    };
    let _ = headers;
    let body = if body.is_end_stream() {
        cache.insert(key, make(Bytes::new()));
        body
    } else {
        let c = cache.clone();
        let limit = usize::try_from(cache.cfg.max_object_size).unwrap_or(usize::MAX);
        boxed(TeeBody::new(
            body,
            limit,
            Box::new(move |b| c.insert(key, make(b))),
        ))
    };
    finish(http::Response::from_parts(parts, body), cache, "MISS")
}

impl Service<Req> for CacheService {
    type Response = Resp;
    type Error = Infallible;
    type Future = BoxFut;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Req) -> BoxFut {
        let clone = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, clone);
        let cache = self.cache.clone();
        Box::pin(async move { Ok(handle(cache, inner, req).await) })
    }
}
