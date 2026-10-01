//! Background revalidation of a stale entry (stale-while-revalidate).
use super::layer::call_svc;
use super::policy::{Ctx, storable};
use super::respond::{Origin, add_validators, build_entry, merge_304};
use super::store::{Entry, HttpCache};
use crate::observe::trace::nz64;
use crate::prelude::{Body, ClientIp, PeerIp, Req, RouteId, RouteSvc, Scheme, TraceCtx, empty};
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri, header};
use http_body_util::BodyExt;
use std::sync::Arc;
use std::time::Duration;

/// What a background request needs from the original one.
pub struct Snapshot {
    uri: Uri,
    headers: HeaderMap,
    client_ip: Option<ClientIp>,
    peer_ip: Option<PeerIp>,
    scheme: Option<Scheme>,
    trace: Option<TraceCtx>,
    route: Option<RouteId>,
}

impl Snapshot {
    pub fn capture(req: &Req) -> Self {
        let mut headers = req.headers().clone();
        for h in [header::IF_NONE_MATCH, header::IF_MODIFIED_SINCE, header::RANGE] {
            headers.remove(h);
        }
        let ext = req.extensions();
        Self {
            uri: req.uri().clone(),
            headers,
            client_ip: ext.get::<ClientIp>().copied(),
            peer_ip: ext.get::<PeerIp>().copied(),
            scheme: ext.get::<Scheme>().copied(),
            trace: ext
                .get::<TraceCtx>()
                .cloned()
                .map(|t| TraceCtx { span_id: nz64(), ..t }),
            route: ext.get::<RouteId>().cloned(),
        }
    }

    fn into_request(self, stored: &HeaderMap) -> Req {
        let mut req = http::Request::new(empty());
        *req.method_mut() = Method::GET;
        *req.uri_mut() = self.uri;
        *req.headers_mut() = self.headers;
        add_validators(req.headers_mut(), stored);
        let ext = req.extensions_mut();
        if let Some(v) = self.client_ip {
            ext.insert(v);
        }
        if let Some(v) = self.peer_ip {
            ext.insert(v);
        }
        if let Some(v) = self.scheme {
            ext.insert(v);
        }
        if let Some(v) = self.trace {
            ext.insert(v);
        }
        if let Some(v) = self.route {
            ext.insert(v);
        }
        req
    }
}

/// Removes the key from the revalidating set even if the task is cancelled.
struct Guard {
    cache: Arc<HttpCache>,
    key: String,
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.cache.end_revalidation(&self.key);
    }
}

/// Collects a body up to `limit` bytes, frame by frame (avoids `Limited`, whose error type trips rustc, rule R5).
fn collect_limited(
    body: Body,
    limit: usize,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Bytes>> + Send>> {
    Box::pin(async move {
        let mut body = body;
        let mut buf = bytes::BytesMut::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.ok()?;
            if let Some(d) = frame.data_ref() {
                if buf.len() + d.len() > limit {
                    return None;
                }
                buf.extend_from_slice(d);
            }
        }
        Some(buf.freeze())
    })
}

pub async fn revalidate(
    cache: Arc<HttpCache>,
    key: String,
    mut inner: RouteSvc,
    snap: Snapshot,
    old: Arc<Entry>,
) {
    let _guard = Guard {
        cache: cache.clone(),
        key: key.clone(),
    };
    let req_headers = snap.headers.clone();
    let req = snap.into_request(&old.headers);
    let Ok(resp) = tokio::time::timeout(Duration::from_secs(30), call_svc(&mut inner, req)).await else {
        return;
    };
    let ctx = Ctx {
        is_get: true,
        sensitive: old.auth_ok,
        has_proxy_failure: false,
    };
    let o = Origin {
        host: &old.host,
        path: &old.path,
        req_headers: &req_headers,
    };
    if resp.status() == StatusCode::NOT_MODIFIED {
        let merged = merge_304(&old.headers, resp.headers());
        if let Some(f) = storable(old.status, &merged, &ctx, &cache.cfg) {
            cache.insert(key, build_entry(old.status, &merged, old.body.clone(), &f, &o));
        }
        return;
    }
    let (parts, body) = resp.into_parts();
    let Some(f) = storable(parts.status, &parts.headers, &ctx, &cache.cfg) else {
        return;
    };
    let limit = usize::try_from(cache.cfg.max_object_size).unwrap_or(usize::MAX);
    if let Some(bytes) = collect_limited(body, limit).await {
        cache.insert(key, build_entry(parts.status, &parts.headers, bytes, &f, &o));
    }
}
