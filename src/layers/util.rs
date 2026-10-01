//! Helpers shared by the security layers.
use crate::observe::fallback::render_error;
use crate::prelude::{IncidentKind, Req, Resp, TraceCtx, simple};
use http::{HeaderValue, StatusCode, header};

/// Gateway error page for a rejecting layer, flagged with the incident kind for the flight recorder.
pub fn reject(status: StatusCode, req: &Req, kind: &'static str) -> Resp {
    let trace = req.extensions().get::<TraceCtx>().cloned().unwrap_or(TraceCtx {
        trace_id: crate::observe::trace::nz128(),
        parent_span: None,
        span_id: 1,
        sampled: true,
    });
    let mut r = render_error(status, req.headers(), &trace);
    r.extensions_mut().insert(IncidentKind(kind));
    r
}

/// JSON error with an optional `WWW-Authenticate` challenge.
pub fn json_error(status: StatusCode, error: &str, challenge: Option<&str>) -> Resp {
    let mut r = simple(
        status,
        "application/json",
        serde_json::json!({ "error": error }).to_string(),
    );
    if let Some(c) = challenge.and_then(|c| HeaderValue::from_str(c).ok()) {
        r.headers_mut().insert(header::WWW_AUTHENTICATE, c);
    }
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r.extensions_mut().insert(IncidentKind("auth"));
    r
}
