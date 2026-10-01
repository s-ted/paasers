//! `FallbackLayer`: turns proxy failures into a maintenance page carrying the Incident ID.
use crate::config::FallbackCfg;
use crate::observe::fallback::{ErrorPage, negotiate, now_rfc3339, render};
use crate::observe::trace::trace_hex;
use crate::prelude::{BoxFut, ProxyFailure, Req, Resp, RouteSvc, TraceCtx, UpstreamUsed, empty};
use http::{HeaderValue, Method, header};
use http_body::Body as _;
use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::Service;

#[derive(Clone)]
pub struct FallbackLayer {
    cfg: Arc<FallbackCfg>,
}

impl FallbackLayer {
    pub fn new(cfg: FallbackCfg) -> Self {
        Self { cfg: Arc::new(cfg) }
    }
}

impl tower::Layer<RouteSvc> for FallbackLayer {
    type Service = Fallback;
    fn layer(&self, inner: RouteSvc) -> Fallback {
        Fallback {
            inner,
            cfg: self.cfg.clone(),
        }
    }
}

#[derive(Clone)]
pub struct Fallback {
    inner: RouteSvc,
    cfg: Arc<FallbackCfg>,
}

/// Replaces `resp` with the configured page. Pure given its inputs.
fn replace(
    resp: Resp,
    cfg: &FallbackCfg,
    accept: Option<&HeaderValue>,
    trace: Option<&TraceCtx>,
    head: bool,
) -> Resp {
    let failure = resp.extensions().get::<ProxyFailure>().cloned();
    let used = resp.extensions().get::<UpstreamUsed>().cloned();
    let origin = resp.status();
    if !cfg.on.contains(&origin.as_u16()) || (failure.is_none() && resp.body().size_hint().exact() != Some(0))
    {
        return resp;
    }
    let id = trace.map(|t| trace_hex(t.trace_id));
    let status = http::StatusCode::from_u16(cfg.status).unwrap_or(http::StatusCode::SERVICE_UNAVAILABLE);
    let ts = now_rfc3339();
    let incident = if cfg.show_incident_id { id.as_deref() } else { None };
    let page = ErrorPage {
        status,
        title: &cfg.title,
        message: &cfg.message,
        incident_id: incident,
        ts: &ts,
    };
    let mut out = render(&page, negotiate(accept));
    out.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
    if head {
        let (parts, _) = out.into_parts();
        out = http::Response::from_parts(parts, empty());
    }
    let mut detail = failure.clone().unwrap_or(ProxyFailure {
        kind: "upstream_status",
        detail: String::new(),
        upstream: None,
    });
    detail.detail = format!("origin_status={} {}", origin.as_u16(), detail.detail)
        .trim_end()
        .to_string();
    out.extensions_mut().insert(detail);
    if let Some(u) = used {
        out.extensions_mut().insert(u);
    }
    out
}

impl Service<Req> for Fallback {
    type Response = Resp;
    type Error = Infallible;
    type Future = BoxFut;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Req) -> BoxFut {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let cfg = self.cfg.clone();
        let accept = req.headers().get(header::ACCEPT).cloned();
        let trace = req.extensions().get::<TraceCtx>().cloned();
        let head = req.method() == Method::HEAD;
        Box::pin(async move {
            let fut = inner.call(req);
            let resp = match fut.await {
                Ok(r) => r,
                Err(e) => match e {},
            };
            Ok(replace(resp, &cfg, accept.as_ref(), trace.as_ref(), head))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::{full, simple};
    use http_body_util::BodyExt;

    fn trace() -> TraceCtx {
        TraceCtx {
            trace_id: 0xfeed,
            parent_span: None,
            span_id: 1,
            sampled: true,
        }
    }

    fn failing(status: u16) -> Resp {
        let mut r = http::Response::new(empty());
        *r.status_mut() = http::StatusCode::from_u16(status).unwrap();
        r.extensions_mut().insert(ProxyFailure {
            kind: "upstream_connect",
            detail: "refused".into(),
            upstream: None,
        });
        r
    }

    async fn text(r: Resp) -> String {
        String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    }

    #[tokio::test]
    async fn replaces_proxy_failure_502_with_503_page() {
        let r = replace(failing(502), &FallbackCfg::default(), None, Some(&trace()), false);
        assert_eq!(r.status(), 503);
        assert_eq!(r.headers()[header::RETRY_AFTER], "30");
        let f = r.extensions().get::<ProxyFailure>().unwrap().clone();
        assert!(f.detail.starts_with("origin_status=502") && f.kind == "upstream_connect");
        assert!(text(r).await.contains("0000000000000000000000000000feed"));
    }

    #[tokio::test]
    async fn keeps_backend_503_with_body() {
        let r = replace(
            simple(http::StatusCode::SERVICE_UNAVAILABLE, "text/plain", "maintenance"),
            &FallbackCfg::default(),
            None,
            Some(&trace()),
            false,
        );
        assert_eq!(text(r).await, "maintenance");
    }

    #[tokio::test]
    async fn replaces_empty_backend_503() {
        let mut r = http::Response::new(empty());
        *r.status_mut() = http::StatusCode::SERVICE_UNAVAILABLE;
        let r = replace(r, &FallbackCfg::default(), None, Some(&trace()), false);
        assert!(text(r).await.contains("Incident ID"));
    }

    #[tokio::test]
    async fn head_has_empty_body() {
        let r = replace(failing(504), &FallbackCfg::default(), None, Some(&trace()), true);
        assert_eq!(r.status(), 503);
        assert!(r.headers().contains_key(header::CONTENT_TYPE));
        assert_eq!(text(r).await, "");
    }

    #[tokio::test]
    async fn passes_200_and_non_listed_status() {
        let r = replace(
            simple(http::StatusCode::OK, "text/plain", "ok"),
            &FallbackCfg::default(),
            None,
            None,
            false,
        );
        assert_eq!(r.status(), 200);
        let cfg = FallbackCfg {
            on: vec![503],
            ..FallbackCfg::default()
        };
        assert_eq!(replace(failing(502), &cfg, None, None, false).status(), 502);
    }

    #[tokio::test]
    async fn json_and_hidden_incident_id() {
        let cfg = FallbackCfg {
            show_incident_id: false,
            status: 502,
            ..FallbackCfg::default()
        };
        let accept = HeaderValue::from_static("application/json");
        let r = replace(failing(504), &cfg, Some(&accept), Some(&trace()), false);
        assert_eq!(r.status(), 502);
        let body = text(r).await;
        assert!(body.starts_with("{\"error\"") && !body.contains("incident_id"));
        let _ = full("");
    }

    #[tokio::test]
    async fn layer_applies_to_service() {
        use tower::Layer;
        let inner = RouteSvc::new(tower::service_fn(|_r: Req| async {
            Ok::<_, Infallible>(failing(502))
        }));
        let mut svc = FallbackLayer::new(FallbackCfg::default()).layer(inner);
        let mut req = http::Request::new(empty());
        req.extensions_mut().insert(trace());
        let resp = std::future::poll_fn(|cx| svc.poll_ready(cx))
            .await
            .map(|()| svc.call(req))
            .unwrap()
            .await
            .unwrap();
        assert_eq!(resp.status(), 503);
    }
}
