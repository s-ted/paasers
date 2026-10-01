//! HTTP types shared by the whole data plane.
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use std::convert::Infallible;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// Single body type used everywhere (requests AND responses).
pub type Body = BoxBody<Bytes, BoxError>;
pub type Req = http::Request<Body>;
pub type Resp = http::Response<Body>;
/// Route service: concrete, cloneable, Sync (required by hyper), infallible.
pub type RouteSvc = tower::util::BoxCloneSyncService<Req, Resp, Infallible>;
pub type BoxFut = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Resp, Infallible>> + Send>>;

pub fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|n| match n {}).boxed()
}
pub fn empty() -> Body {
    Empty::<Bytes>::new().map_err(|n| match n {}).boxed()
}
/// Converts any body (Incoming, compression, ...) into `Body`.
pub fn boxed<B>(b: B) -> Body
where
    B: http_body::Body<Data = Bytes> + Send + Sync + 'static,
    B::Error: Into<BoxError>,
{
    b.map_err(Into::into).boxed()
}
pub fn map_resp<B>(r: http::Response<B>) -> Resp
where
    B: http_body::Body<Data = Bytes> + Send + Sync + 'static,
    B::Error: Into<BoxError>,
{
    r.map(boxed)
}
/// Simple response (status + text), without panicking.
pub fn simple(status: http::StatusCode, ctype: &'static str, body: impl Into<Bytes>) -> Resp {
    let mut r = http::Response::new(full(body));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static(ctype));
    r
}

#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub std::net::IpAddr);
#[derive(Clone, Copy, Debug)]
pub struct Scheme(pub &'static str);
#[derive(Clone, Debug)]
pub struct TraceCtx {
    pub trace_id: u128,
    pub parent_span: Option<u64>,
    pub span_id: u64,
    pub sampled: bool,
}
#[derive(Clone, Debug)]
pub struct RouteId(pub std::sync::Arc<str>);
#[derive(Clone, Copy, Debug)]
pub struct ApiKeyAuthenticated;
#[derive(Clone, Debug)]
pub struct CountryCode(pub [u8; 2]);
#[derive(Clone, Debug)]
pub struct ProxyFailure {
    pub kind: &'static str,
    pub detail: String,
    pub upstream: Option<std::net::SocketAddr>,
}
#[derive(Clone, Debug)]
pub struct UpstreamUsed(pub std::net::SocketAddr);
#[derive(Clone, Copy, Debug)]
pub struct RequestStart(pub std::time::Instant);
#[derive(Clone, Copy, Debug)]
pub struct IncidentKind(pub &'static str);
#[derive(Clone, Copy, Debug)]
pub struct CacheStatus(pub &'static str);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_sets_status_and_ctype() {
        let r = simple(http::StatusCode::IM_A_TEAPOT, "text/plain", "x");
        assert_eq!(r.status(), http::StatusCode::IM_A_TEAPOT);
        assert_eq!(r.headers()[http::header::CONTENT_TYPE], "text/plain");
    }
}
