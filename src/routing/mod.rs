//! Runtime snapshot: host table and per-route services.
pub mod host;
pub mod stack;
pub mod table;

pub use table::HostTable;

use crate::config::{Config, Limits, RouteCfg};
use crate::prelude::{Req, RouteSvc};
use crate::proxy::Balancer;
use crate::server::Shared;
use ipnet::IpNet;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("router: {0}")]
    Router(String),
    #[error("gatekeeper: {0}")]
    Gatekeeper(String),
    #[error("jwt: {0}")]
    Jwt(String),
    #[error("geoip: {0}")]
    GeoIp(String),
}

pub struct RouteRuntime {
    pub id: Arc<str>,
    pub hosts: Vec<String>,
    pub cfg: Arc<RouteCfg>,
    pub service: RouteSvc,
    pub balancer: Arc<Balancer>,
    pub cache: Option<Arc<crate::cache::HttpCache>>,
    pub redirect_https: bool,
}

pub struct Runtime {
    pub table: HostTable,
    pub trusted_proxies: Vec<IpNet>,
    pub https_port: Option<u16>,
    pub limits: Limits,
    pub generation: u64,
    pub config: Arc<Config>,
}

/// Every upstream address referenced by the configuration.
pub fn active_upstreams(cfg: &Config) -> HashSet<SocketAddr> {
    cfg.routes
        .iter()
        .flat_map(|r| r.upstreams.iter().map(|u| u.addr))
        .collect()
}

/// Implicit route used when the configuration defines none: serves the current directory on any host.
fn default_route(cfg: &Arc<Config>, shared: &Shared) -> Result<Arc<RouteRuntime>, BuildError> {
    let route = RouteCfg {
        id: Arc::from("(default)"),
        hosts: Vec::new(),
        tls: None,
        redirect_https: false,
        upstreams: Vec::new(),
        static_files: Some(crate::config::StaticCfg::default()),
        health: crate::config::HealthCfg::default(),
        request_timeout: std::time::Duration::from_secs(60),
        cache: None,
        compression: Some(crate::config::CompressionCfg::default()),
        geoip: None,
        rate_limits: Vec::new(),
        gatekeeper: None,
        jwt: None,
        api_keys: None,
        transform: None,
        fallback: None,
        retry: false,
    };
    let balancer = Arc::new(Balancer::new(&[], &shared.health));
    let service = stack::build_stack(
        &route,
        balancer.clone(),
        shared,
        Arc::new(cfg.gateway.trusted_proxies.clone()),
    )?;
    Ok(Arc::new(RouteRuntime {
        id: route.id.clone(),
        hosts: Vec::new(),
        cfg: Arc::new(route),
        service,
        balancer,
        cache: None,
        redirect_https: false,
    }))
}

pub fn build(cfg: &Arc<Config>, shared: &Shared) -> Result<Runtime, BuildError> {
    let trusted = Arc::new(cfg.gateway.trusted_proxies.clone());
    let mut probed: HashSet<SocketAddr> = HashSet::new();
    let routes = cfg
        .routes
        .iter()
        .map(|r| -> Result<_, BuildError> {
            let balancer = Arc::new(Balancer::new(&r.upstreams, &shared.health));
            // The first route declaring an address decides its probe configuration.
            for u in &r.upstreams {
                if probed.insert(u.addr) {
                    shared.health.ensure_checker(u.addr, &r.health, &shared.client);
                }
            }
            Ok(Arc::new(RouteRuntime {
                id: r.id.clone(),
                hosts: r.hosts.clone(),
                cfg: Arc::new(r.clone()),
                service: stack::build_stack(
                    r,
                    balancer.clone(),
                    shared,
                    trusted.clone(),
                )?,
                balancer,
                cache: r
                    .cache
                    .as_ref()
                    .map(|c| shared.caches.get_or_create(&r.id, c, &r.upstreams)),
                redirect_https: r.redirect_https,
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    shared
        .limiters
        .retain_routes(&cfg.routes.iter().map(|r| r.id.clone()).collect());
    shared
        .caches
        .retain(&cfg.routes.iter().map(|r| r.id.clone()).collect());
    Ok(Runtime {
        table: if routes.is_empty() {
            HostTable::catch_all(default_route(cfg, shared)?)
        } else {
            HostTable::new(routes)?
        },
        trusted_proxies: cfg.gateway.trusted_proxies.clone(),
        https_port: cfg.gateway.listen_https.map(|a| a.port()),
        limits: cfg.gateway.limits.clone(),
        generation: shared.generation.fetch_add(1, Ordering::Relaxed) + 1,
        config: cfg.clone(),
    })
}

/// Removes headers that only the gateway may set, so clients cannot spoof them.
pub fn strip_spoofable(req: &mut Req) {
    const SPOOFABLE: &[&str] = &[
        "x-user-id",
        "x-user-email",
        "x-user-roles",
        "x-jwt-claims",
        "x-api-key-name",
        "x-country-code",
    ];
    SPOOFABLE.iter().for_each(|h| {
        req.headers_mut().remove(*h);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;

    pub fn cfg(src: &str) -> Arc<Config> {
        Arc::new(parse_str(src, &|_| None).unwrap())
    }

    #[test]
    fn build_two_routes_lookup() {
        let c = cfg(
            "route \"a.com\" \"www.a.com\" { upstream \"10.0.0.1:80\" }\nroute \"*.b.com\" { upstream \"10.0.0.2:80\" }",
        );
        let rt = build(&c, &Shared::new()).unwrap();
        assert_eq!(&*rt.table.lookup("www.a.com").unwrap().id, "a.com");
        assert_eq!(&*rt.table.lookup("a.com").unwrap().id, "a.com");
        assert_eq!(&*rt.table.lookup("x.b.com").unwrap().id, "*.b.com");
        assert!(rt.table.lookup("nope.com").is_none());
        assert_eq!(rt.generation, 1);
        assert_eq!(rt.table.routes().len(), 2);
    }

    #[test]
    fn health_state_survives_rebuild() {
        let c = cfg("route \"a.com\" { upstream \"10.0.0.1:80\" }");
        let shared = Shared::new();
        let addr: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let first = build(&c, &shared).unwrap();
        let h = shared.health.get(addr).unwrap();
        h.report_failure_passive();
        let second = build(&c, &shared).unwrap();
        let again = &second.table.lookup("a.com").unwrap().balancer.upstreams[0].health;
        assert!(Arc::ptr_eq(&h, again) && !again.is_healthy());
        assert!(first.table.lookup("a.com").unwrap().balancer.pick().is_none());
    }

    #[test]
    fn generation_increments_on_each_build() {
        let c = cfg("");
        let shared = Shared::new();
        assert_eq!(build(&c, &shared).unwrap().generation, 1);
        assert_eq!(build(&c, &shared).unwrap().generation, 2);
    }

    #[test]
    fn strip_spoofable_removes_headers() {
        let mut req = http::Request::new(crate::prelude::empty());
        req.headers_mut().insert("x-user-id", "1".parse().unwrap());
        req.headers_mut().insert("x-keep", "1".parse().unwrap());
        strip_spoofable(&mut req);
        assert!(!req.headers().contains_key("x-user-id") && req.headers().contains_key("x-keep"));
    }
}
