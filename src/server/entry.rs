//! Entry service: the first service called for each request.
use super::Shared;
use crate::observe::{fallback::render_error, trace};
use crate::prelude::{
    BoxFut, ClientIp, Req, RequestStart, Resp, RouteId, RouteSvc, Scheme, TraceCtx, boxed, empty,
};
use crate::routing::{Runtime, strip_spoofable};
use arc_swap::ArcSwap;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use http_body_util::Limited;
use ipnet::IpNet;
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

/// TCP peer, or the right-most untrusted `X-Forwarded-For` address when the peer is a trusted proxy.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let peer = peer.to_canonical();
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|n| n.contains(ip));
    if !is_trusted(&peer) {
        return peer;
    }
    let xff = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(",");
    for part in xff.rsplit(',') {
        match part.trim().parse::<IpAddr>() {
            Ok(ip) => {
                let ip = ip.to_canonical();
                if !is_trusted(&ip) {
                    return ip;
                }
            }
            Err(_) => return peer,
        }
    }
    peer
}

/// Normalized host from `:authority` or `Host`: port stripped, lowercase, no trailing dot.
pub fn request_host(uri: &http::Uri, headers: &HeaderMap) -> Option<String> {
    let raw = match uri.host() {
        Some(h) => h.to_string(),
        None => strip_port(headers.get(header::HOST)?.to_str().ok()?).to_string(),
    };
    let h = raw.to_ascii_lowercase();
    let h = h.strip_suffix('.').unwrap_or(&h);
    let ok = !h.is_empty()
        && h.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    ok.then(|| h.to_string())
}

fn strip_port(h: &str) -> &str {
    match h.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(':') && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => h,
    }
}

pub fn https_location(host: &str, path_and_query: &str, https_port: Option<u16>) -> String {
    match https_port {
        Some(p) if p != 443 => format!("https://{host}:{p}{path_and_query}"),
        _ => format!("https://{host}{path_and_query}"),
    }
}

fn redirect(location: &str) -> Resp {
    let mut r = http::Response::new(empty());
    *r.status_mut() = StatusCode::MOVED_PERMANENTLY;
    if let Ok(v) = HeaderValue::from_str(location) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    r
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
        let (peer, scheme, current, _shared) =
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
                let Some(route) = rt.table.lookup(&host) else {
                    break 'resp reject(StatusCode::NOT_FOUND);
                };
                if scheme.0 == "http" && route.redirect_https {
                    let pq = parts.uri.path_and_query().map_or("/", |p| p.as_str());
                    break 'resp redirect(&https_location(&host, pq, rt.https_port));
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
                parts.extensions.insert(scheme);
                parts.extensions.insert(trace.clone());
                parts.extensions.insert(RouteId(route.id.clone()));
                parts.extensions.insert(RequestStart(start));
                let mut req = http::Request::from_parts(parts.clone(), boxed(Limited::new(body, limit)));
                strip_spoofable(&mut req);
                call_route(route.service.clone(), req).await
            };
            let status = resp.status();
            let (method, path) = (parts.method.as_str(), parts.uri.path());
            if status.is_server_error() {
                tracing::warn!(target: "access", method, path, status = status.as_u16(), dur_ms = start.elapsed().as_millis() as u64, trace_id = %trace::trace_hex(trace.trace_id), client_ip = %ip);
            } else if status.is_client_error() {
                tracing::info!(target: "access", method, path, status = status.as_u16(), dur_ms = start.elapsed().as_millis() as u64, trace_id = %trace::trace_hex(trace.trace_id), client_ip = %ip);
            } else {
                tracing::debug!(target: "access", method, path, status = status.as_u16(), dur_ms = start.elapsed().as_millis() as u64, trace_id = %trace::trace_hex(trace.trace_id), client_ip = %ip);
            }
            Ok(finish(resp, &trace))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xff(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        h
    }

    fn nets(s: &[&str]) -> Vec<IpNet> {
        s.iter().map(|x| x.parse().unwrap()).collect()
    }

    #[test]
    fn client_ip_ignores_xff_from_untrusted() {
        let ip = client_ip("1.2.3.4".parse().unwrap(), &xff("9.9.9.9"), &[]);
        assert_eq!(ip.to_string(), "1.2.3.4");
    }

    #[test]
    fn client_ip_uses_rightmost_untrusted_xff() {
        let t = nets(&["10.0.0.0/8"]);
        let ip = client_ip(
            "10.0.0.1".parse().unwrap(),
            &xff("6.6.6.6, 8.8.8.8, 10.0.0.2"),
            &t,
        );
        assert_eq!(ip.to_string(), "8.8.8.8");
        let ip = client_ip("10.0.0.1".parse().unwrap(), &xff("garbage"), &t);
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn client_ip_ipv4_mapped_canonical() {
        let ip = client_ip("::ffff:1.2.3.4".parse().unwrap(), &HeaderMap::new(), &[]);
        assert_eq!(ip.to_string(), "1.2.3.4");
    }

    #[test]
    fn host_from_authority_strip_port_lower_trailing_dot() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("WWW.Example.COM.:8443"));
        let uri: http::Uri = "/x".parse().unwrap();
        assert_eq!(request_host(&uri, &h).as_deref(), Some("www.example.com"));
        let uri: http::Uri = "https://Auth.Example.com:444/x".parse().unwrap();
        assert_eq!(
            request_host(&uri, &HeaderMap::new()).as_deref(),
            Some("auth.example.com")
        );
    }

    #[test]
    fn missing_or_invalid_host_is_none() {
        let uri: http::Uri = "/x".parse().unwrap();
        assert!(request_host(&uri, &HeaderMap::new()).is_none());
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("a/b{}"));
        assert!(request_host(&uri, &h).is_none());
    }

    #[test]
    fn redirect_https_preserves_path_query_and_port() {
        assert_eq!(
            https_location("a.com", "/x?y=1", Some(443)),
            "https://a.com/x?y=1"
        );
        assert_eq!(https_location("a.com", "/x", Some(8443)), "https://a.com:8443/x");
        assert_eq!(https_location("a.com", "/", None), "https://a.com/");
    }
}
