//! Assembly of a route's Tower stack (layers are added by later phases, in the order of PLAN §1.3).
use crate::prelude::{Req, Resp, RouteSvc, simple};
use std::convert::Infallible;

/// Base service used until the proxy exists (P5).
pub fn placeholder_service() -> RouteSvc {
    let svc = tower::service_fn(|_req: Req| async {
        Ok::<Resp, Infallible>(simple(
            http::StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            "not wired",
        ))
    });
    RouteSvc::new(svc)
}

/// Builds the full service of one route. Inner to outer, each step returns a `RouteSvc` (rule R5).
pub fn build_stack() -> RouteSvc {
    placeholder_service()
}
