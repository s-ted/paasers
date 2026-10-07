//! Assembly of a route's Tower stack (layers are added by later phases, in the order of PLAN §1.3).
use super::BuildError;
use crate::cache::CacheLayer;
use crate::config::RouteCfg;
use crate::gatekeeper::GatekeeperLayer;
use crate::layers::apikey::ApiKeyLayer;
use crate::layers::compression;
use crate::layers::fallback::FallbackLayer;
use crate::layers::geoip::GeoIpLayer;
use crate::layers::ipallow::IpAllowLayer;
use crate::layers::jwt::JwtLayer;
use crate::layers::ratelimit::RateLimitLayer;
use crate::layers::transform::TransformLayer;
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

/// Reverse proxy terminal service with its fallback page and optional cache.
fn proxied(route: &RouteCfg, balancer: Arc<Balancer>, shared: &Shared, trusted: Arc<Vec<IpNet>>) -> RouteSvc {
    let svc = RouteSvc::new(ProxyService::new(
        balancer,
        shared.client.clone(),
        route.request_timeout,
        trusted,
        shared.tunnels.clone(),
        route.retry,
    ));
    let svc = match &route.fallback {
        Some(f) => RouteSvc::new(FallbackLayer::new(f.clone()).layer(svc)),
        None => svc,
    };
    match &route.cache {
        Some(c) => {
            let cache = shared.caches.get_or_create(&route.id, c, &route.upstreams);
            RouteSvc::new(CacheLayer::new(cache).layer(svc))
        }
        None => svc,
    }
}

/// Builds the full service of one route. Inner to outer, each step returns a `RouteSvc` (rule R5).
pub fn build_stack(
    route: &RouteCfg,
    balancer: Arc<Balancer>,
    shared: &Shared,
    trusted: Arc<Vec<IpNet>>,
) -> Result<RouteSvc, BuildError> {
    let svc = match &route.static_files {
        Some(sf) => {
            let files = crate::staticfiles::StaticService::new(sf)
                .map_err(|e| BuildError::Router(format!("static {}: {e}", sf.root.display())))?;
            RouteSvc::new(files)
        }
        None => proxied(route, balancer, shared, trusted),
    };
    // Compression sits above the cache: hits are compressed too, and the cache stores one representation.
    let svc = match &route.compression {
        Some(c) => compression::wrap(svc, c),
        None => svc,
    };
    let svc = match &route.transform {
        Some(t) => RouteSvc::new(TransformLayer::new(t).layer(svc)),
        None => svc,
    };
    let svc = match &route.jwt {
        Some(j) => {
            let layer = JwtLayer::new(j, &route.id).map_err(BuildError::Jwt)?;
            RouteSvc::new(layer.layer(svc))
        }
        None => svc,
    };
    let svc = match &route.api_keys {
        Some(k) => {
            let layer = ApiKeyLayer::new(k, route.jwt.is_some())
                .ok_or_else(|| BuildError::Router("invalid api-keys configuration".into()))?;
            RouteSvc::new(layer.layer(svc))
        }
        None => svc,
    };
    let svc = match &route.gatekeeper {
        Some(g) => {
            let gate = shared
                .gate
                .get()
                .ok_or_else(|| BuildError::Gatekeeper("state not initialised".into()))?;
            let layer = GatekeeperLayer::new(&route.id, g, route.tls.is_some(), gate)
                .map_err(|e| BuildError::Gatekeeper(e.to_string()))?;
            RouteSvc::new(layer.layer(svc))
        }
        None => svc,
    };
    let svc = if route.rate_limits.is_empty() {
        svc
    } else {
        let layer = RateLimitLayer::new(&route.id, &route.rate_limits, &shared.limiters)
            .ok_or_else(|| BuildError::Router("invalid rate-limit configuration".into()))?;
        RouteSvc::new(layer.layer(svc))
    };
    let svc = match &route.geoip {
        Some(g) => {
            let layer = GeoIpLayer::new(g, &shared.geoip).map_err(|e| BuildError::GeoIp(e.to_string()))?;
            RouteSvc::new(layer.layer(svc))
        }
        None => svc,
    };
    // Outermost: a refused client spends no rate-limit budget, no GeoIP lookup, no backend.
    let svc = match &route.allow_ips {
        Some(nets) => RouteSvc::new(IpAllowLayer::new(nets).layer(svc)),
        None => svc,
    };
    Ok(svc)
}
