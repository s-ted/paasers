//! Reverse proxy service: weighted upstream choice, header rewriting, retry, WebSocket tunnel.
pub mod balancer;
pub mod client;
pub mod headers;
pub mod health;
pub mod upgrade;

pub use balancer::Balancer;
pub use client::{UpstreamClient, new_client};
pub use health::{HealthRegistry, UpstreamHealth};

use crate::error::GatewayError;
use crate::prelude::{
    Body, BoxFut, ClientIp, PeerIp, ProxyFailure, Req, Resp, Scheme, TraceCtx, UpstreamUsed, boxed, empty,
};
use headers::ReqCtx;
use http::{HeaderMap, Method, StatusCode, Version, header};
use http_body::Body as _;
use http_body_util::LengthLimitError;
use ipnet::IpNet;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Poll};
use std::time::Duration;

/// Response without body carrying the failure description (rendered by the fallback layer).
pub fn failure(err: &GatewayError, kind: &'static str, upstream: Option<SocketAddr>) -> Resp {
    let mut r = http::Response::new(empty());
    *r.status_mut() = err.status();
    r.extensions_mut().insert(ProxyFailure {
        kind,
        detail: err.to_string(),
        upstream,
    });
    r
}

#[derive(Debug)]
enum SendError {
    Timeout,
    Connect(String),
    TooLarge,
    BadUri,
    Other(String),
}

fn is_length_limit(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    for _ in 0..10 {
        let Some(err) = cur else { return false };
        if err.downcast_ref::<LengthLimitError>().is_some() {
            return true;
        }
        cur = err.source();
    }
    false
}

#[derive(Clone)]
pub struct ProxyService {
    balancer: Arc<Balancer>,
    client: UpstreamClient,
    request_timeout: Duration,
    trusted: Arc<Vec<IpNet>>,
    tunnels: Arc<AtomicUsize>,
}

impl ProxyService {
    pub fn new(
        balancer: Arc<Balancer>,
        client: UpstreamClient,
        request_timeout: Duration,
        trusted: Arc<Vec<IpNet>>,
        tunnels: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            balancer,
            client,
            request_timeout,
            trusted,
            tunnels,
        }
    }

    async fn send(
        &self,
        addr: SocketAddr,
        pq: &str,
        method: Method,
        headers: HeaderMap,
        body: Body,
    ) -> Result<http::Response<hyper::body::Incoming>, SendError> {
        let uri = http::Uri::builder()
            .scheme("http")
            .authority(addr.to_string())
            .path_and_query(pq)
            .build()
            .map_err(|_| SendError::BadUri)?;
        let mut req = http::Request::new(body);
        *req.method_mut() = method;
        *req.uri_mut() = uri;
        *req.version_mut() = Version::HTTP_11;
        *req.headers_mut() = headers;
        match tokio::time::timeout(self.request_timeout, self.client.request(req)).await {
            Err(_) => Err(SendError::Timeout),
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) if e.is_connect() => Err(SendError::Connect(e.to_string())),
            Ok(Err(e)) if is_length_limit(&e) => Err(SendError::TooLarge),
            Ok(Err(e)) => Err(SendError::Other(e.to_string())),
        }
    }

    async fn forward(self, mut req: Req) -> Resp {
        let Some((addr, health)) = self.balancer.pick().map(|u| (u.addr, u.health.clone())) else {
            return failure(&GatewayError::NoHealthyUpstream, "no_healthy_upstream", None);
        };
        let upgrade = headers::is_upgrade(req.headers());
        let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));
        let (mut parts, body) = req.into_parts();
        let pq = parts.uri.path_and_query().map_or("/", |p| p.as_str()).to_string();
        let host = parts
            .headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .or_else(|| parts.uri.authority().map(|a| a.to_string()))
            .unwrap_or_default();
        let (Some(client_ip), Some(trace)) = (
            parts.extensions.get::<ClientIp>().copied(),
            parts.extensions.get::<TraceCtx>().cloned(),
        ) else {
            return failure(
                &GatewayError::BadRequest("missing request context"),
                "bad_request",
                None,
            );
        };
        let peer_ip = parts.extensions.get::<PeerIp>().map_or(client_ip.0, |p| p.0);
        let scheme = parts.extensions.get::<Scheme>().map_or("http", |s| s.0);
        let retryable = !upgrade
            && matches!(
                parts.method,
                Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
            )
            && body.size_hint().exact() == Some(0);
        let ctx = ReqCtx {
            peer_ip,
            peer_trusted: self.trusted.iter().any(|n| n.contains(&peer_ip)),
            client_ip: client_ip.0,
            scheme,
            host: &host,
            trace: &trace,
            is_upgrade: upgrade,
        };
        headers::prepare_request(&mut parts.headers, &ctx);
        let retry_src = retryable.then(|| (parts.method.clone(), parts.headers.clone()));
        let mut used = addr;
        let mut result = self.send(addr, &pq, parts.method, parts.headers, body).await;
        if let (Err(SendError::Connect(_)), Some((method, headers))) = (&result, retry_src) {
            health.report_failure_passive();
            if let Some((a2, _)) = self.balancer.pick_excluding(addr).map(|u| (u.addr, ())) {
                used = a2;
                result = self.send(a2, &pq, method, headers, empty()).await;
                if matches!(result, Err(SendError::Connect(_)))
                    && let Some(h) = self.balancer.upstreams.iter().find(|u| u.addr == a2)
                {
                    h.health.report_failure_passive();
                }
            }
        } else if matches!(result, Err(SendError::Connect(_))) {
            health.report_failure_passive();
        }
        match result {
            Ok(resp) => self.finish(resp, used, client_upgrade, upgrade),
            Err(SendError::Timeout) => {
                failure(&GatewayError::UpstreamTimeout, "upstream_timeout", Some(used))
            }
            Err(SendError::Connect(m)) => {
                failure(&GatewayError::UpstreamConnect(m), "upstream_connect", Some(used))
            }
            Err(SendError::TooLarge) => failure(&GatewayError::PayloadTooLarge, "payload_too_large", None),
            Err(SendError::BadUri) => failure(
                &GatewayError::BadRequest("invalid request target"),
                "bad_request",
                None,
            ),
            Err(SendError::Other(m)) => failure(&GatewayError::Upstream(m), "upstream_error", Some(used)),
        }
    }

    fn finish(
        &self,
        mut resp: http::Response<hyper::body::Incoming>,
        addr: SocketAddr,
        client_upgrade: Option<hyper::upgrade::OnUpgrade>,
        upgrade: bool,
    ) -> Resp {
        if let Some(h) = self.balancer.upstreams.iter().find(|u| u.addr == addr) {
            h.health.report_success_passive();
        }
        let switching = upgrade && resp.status() == StatusCode::SWITCHING_PROTOCOLS;
        if let (true, Some(cu)) = (switching, client_upgrade) {
            let uu = hyper::upgrade::on(&mut resp);
            tokio::spawn(upgrade::tunnel(cu, uu, self.tunnels.clone()));
        }
        headers::prepare_response(resp.headers_mut(), switching);
        resp.extensions_mut().insert(UpstreamUsed(addr));
        resp.map(boxed)
    }
}

impl tower::Service<Req> for ProxyService {
    type Response = Resp;
    type Error = Infallible;
    type Future = BoxFut;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Req) -> BoxFut {
        let this = self.clone();
        Box::pin(async move { Ok(this.forward(req).await) })
    }
}
