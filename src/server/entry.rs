//! Entry service: the first service called for each request.
use super::Shared;
use super::request::{ACME_PREFIX, acme_challenge, client_ip, https_location, redirect, request_host};
use crate::observe::body_watch::WatchBody;
use crate::observe::{Incident, fallback::render_error, trace};
use crate::prelude::{
    BoxFut, ClientIp, IncidentKind, PeerIp, ProxyFailure, Req, RequestStart, Resp, RouteId, RouteSvc, Scheme,
    TraceCtx, UpstreamUsed, boxed,
};
use crate::routing::{Runtime, strip_spoofable};
use arc_swap::ArcSwap;
use http::{HeaderValue, StatusCode, header};
use http_body_util::Limited;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tower::Service;

#[derive(Clone)]
pub struct EntryService {
    pub peer: SocketAddr,
    pub scheme: Scheme,
    pub current: Arc<ArcSwap<Runtime>>,
    pub shared: Arc<Shared>,
}

/// Concrete (non generic) call, which avoids the rustc "Send not general enough" error (R5).
fn call_route(svc: RouteSvc, req: Req) -> BoxFut2 {
    let mut svc = svc;
    Box::pin(async move {
        let ready = std::future::poll_fn(|cx| svc.poll_ready(cx)).await;
        let fut = match ready {
            Ok(()) => svc.call(req),
            Err(e) => match e {},
        };
        match fut.await {
            Ok(r) => r,
            Err(e) => match e {},
        }
    })
}

type BoxFut2 = std::pin::Pin<Box<dyn std::future::Future<Output = Resp> + Send>>;

/// Access log, flight recorder and streaming error watch for one response.
fn observe_response(
    resp: Resp,
    shared: &Arc<Shared>,
    trace: &TraceCtx,
    parts: &http::request::Parts,
    ip: IpAddr,
    start: Instant,
) -> Resp {
    let status = resp.status();
    let trace_id = trace::trace_hex(trace.trace_id);
    let dur_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let (method, path) = (parts.method.as_str(), parts.uri.path());
    let fields = (status.as_u16(), dur_ms);
    if status.is_server_error() {
        tracing::warn!(target: "access", method, path, status = fields.0, dur_ms, %trace_id, client_ip = %ip);
    } else if status.is_client_error() {
        tracing::info!(target: "access", method, path, status = fields.0, dur_ms, %trace_id, client_ip = %ip);
    } else {
        tracing::debug!(target: "access", method, path, status = fields.0, dur_ms, %trace_id, client_ip = %ip);
    }
    let failure = resp.extensions().get::<ProxyFailure>().cloned();
    let upstream = resp.extensions().get::<UpstreamUsed>().map(|u| u.0.to_string());
    let base = {
        let kind = failure
            .as_ref()
            .map(|f| f.kind)
            .or_else(|| resp.extensions().get::<IncidentKind>().map(|k| k.0))
            .unwrap_or("http");
        let mut i = Incident::new(trace_id.clone(), kind);
        i.status = Some(status.as_u16());
        i.method = Some(method.to_string());
        i.host = request_host(&parts.uri, &parts.headers);
        i.path = Some(path.to_string());
        i.route_id = parts.extensions.get::<RouteId>().map(|r| r.0.to_string());
        i.client_ip = Some(ip.to_string());
        i.upstream = upstream.or_else(|| failure.as_ref().and_then(|f| f.upstream).map(|a| a.to_string()));
        i.duration_ms = Some(dur_ms);
        i.detail = failure
            .as_ref()
            .map(|f| crate::observe::recorder::truncate(&f.detail, 512));
        if let Some(ua) = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
        {
            i = i.with_user_agent(ua);
        }
        i
    };
    if status.as_u16() >= 400 || failure.is_some() {
        shared.recorder.record(base.clone());
    }
    if resp.extensions().get::<UpstreamUsed>().is_none() {
        return resp;
    }
    let recorder = shared.recorder.clone();
    resp.map(|body| {
        let on_error = Box::new(move |msg: String| {
            let mut i = base;
            i.kind = "upstream_body_error";
            recorder.record(i.with_detail(&msg));
        });
        boxed(WatchBody::new(body, on_error))
    })
}

fn finish(mut resp: Resp, trace: &TraceCtx) -> Resp {
    if let Ok(v) = HeaderValue::from_str(&trace::traceparent(trace)) {
        resp.headers_mut().insert("traceparent", v);
    }
    if let Ok(v) = HeaderValue::from_str(&trace::trace_hex(trace.trace_id)) {
        resp.headers_mut().insert("x-request-id", v);
    }
    resp
}

impl tower::Service<http::Request<hyper::body::Incoming>> for EntryService {
    type Response = Resp;
    type Error = Infallible;
    type Future = BoxFut;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<hyper::body::Incoming>) -> BoxFut {
        let (peer, scheme, current, shared) =
            (self.peer, self.scheme, self.current.clone(), self.shared.clone());
        Box::pin(async move {
            let start = Instant::now();
            let rt = current.load_full();
            let (mut parts, body) = req.into_parts();
            let ip = client_ip(peer.ip(), &parts.headers, &rt.trusted_proxies);
            let trace = trace::from_headers(&parts.headers);
            let reject = |status: StatusCode| render_error(status, &parts.headers, &trace);
            let resp = 'resp: {
                let Some(host) = request_host(&parts.uri, &parts.headers) else {
                    break 'resp reject(StatusCode::BAD_REQUEST);
                };
                if scheme.0 == "http"
                    && let Some(token) = parts.uri.path().strip_prefix(ACME_PREFIX)
                {
                    break 'resp acme_challenge(&shared, token);
                }
                let Some(route) = rt.table.lookup(&host) else {
                    break 'resp reject(StatusCode::NOT_FOUND);
                };
                if scheme.0 == "http" && route.redirect_https {
                    let pq = parts.uri.path_and_query().map_or("/", |p| p.as_str());
                    let bound = shared.https_port.load(std::sync::atomic::Ordering::Relaxed);
                    let port = if bound != 0 { Some(bound) } else { rt.https_port };
                    break 'resp redirect(&https_location(&host, pq, port));
                }
                let via_loop = parts.headers.get_all(header::VIA).iter().any(|v| {
                    v.to_str()
                        .is_ok_and(|s| s.to_ascii_lowercase().contains("paasers"))
                });
                if via_loop {
                    break 'resp reject(StatusCode::LOOP_DETECTED);
                }
                let too_big = parts
                    .headers
                    .get(header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .is_some_and(|n| n > rt.limits.max_body);
                if too_big {
                    break 'resp reject(StatusCode::PAYLOAD_TOO_LARGE);
                }
                let limit = usize::try_from(rt.limits.max_body).unwrap_or(usize::MAX);
                parts.extensions.insert(ClientIp(ip));
                parts.extensions.insert(PeerIp(peer.ip().to_canonical()));
                parts.extensions.insert(scheme);
                parts.extensions.insert(trace.clone());
                parts.extensions.insert(RouteId(route.id.clone()));
                parts.extensions.insert(RequestStart(start));
                let mut req = http::Request::from_parts(parts.clone(), boxed(Limited::new(body, limit)));
                strip_spoofable(&mut req);
                call_route(route.service.clone(), req).await
            };
            let resp = observe_response(resp, &shared, &trace, &parts, ip, start);
            Ok(finish(resp, &trace))
        })
    }
}
