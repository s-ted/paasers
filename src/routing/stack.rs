//! Assembly of a route's Tower stack (layers are added by later phases, in the order of PLAN §1.3).
use super::BuildError;
use crate::cache::CacheLayer;
use crate::config::RouteCfg;
use crate::gatekeeper::GatekeeperLayer;
use crate::layers::fallback::FallbackLayer;
use crate::prelude::{Req, Resp, RouteSvc, simple};
use crate::proxy::{Balancer, ProxyService};
use crate::server::Shared;
use ipnet::IpNet;
use std::convert::Infallible;
use std::sync::Arc;
use tower::Layer;

/// Service that always answers 503, for tests that do not need a real proxy.
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
pub fn build_stack(
    route: &RouteCfg,
    balancer: Arc<Balancer>,
    shared: &Shared,
    trusted: Arc<Vec<IpNet>>,
    https_port: Option<u16>,
) -> Result<RouteSvc, BuildError> {
    let svc = RouteSvc::new(ProxyService::new(
        balancer,
        shared.client.clone(),
        route.request_timeout,
        trusted,
        shared.tunnels.clone(),
    ));
    let svc = RouteSvc::new(FallbackLayer::new(route.fallback.clone()).layer(svc));
    let svc = match &route.cache {
        Some(c) => {
            let cache = shared.caches.get_or_create(&route.id, c, &route.upstreams);
            RouteSvc::new(CacheLayer::new(cache).layer(svc))
        }
        None => svc,
    };
    let svc = match &route.gatekeeper {
        Some(g) => {
            let gate = shared
                .gate
                .get()
                .ok_or_else(|| BuildError::Gatekeeper("state not initialised".into()))?;
            let layer =
                GatekeeperLayer::new(&route.id, &route.hosts, g, route.tls.is_some(), https_port, gate)
                    .map_err(|e| BuildError::Gatekeeper(e.to_string()))?;
            RouteSvc::new(layer.layer(svc))
        }
        None => svc,
    };
    Ok(svc)
}
