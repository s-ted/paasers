//! Runtime snapshot: host table and per-route services.
pub mod host;
pub mod stack;
pub mod table;

pub use table::HostTable;

use crate::config::{Config, Limits, RouteCfg};
use crate::prelude::{Req, RouteSvc};
use crate::server::Shared;
use ipnet::IpNet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("router: {0}")]
    Router(String),
}

pub struct RouteRuntime {
    pub id: Arc<str>,
    pub hosts: Vec<String>,
    pub cfg: Arc<RouteCfg>,
    pub service: RouteSvc,
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

pub fn build(cfg: &Arc<Config>, shared: &Shared) -> Result<Runtime, BuildError> {
    let routes = cfg
        .routes
        .iter()
        .map(|r| {
            Arc::new(RouteRuntime {
                id: r.id.clone(),
                hosts: r.hosts.clone(),
                cfg: Arc::new(r.clone()),
                service: stack::build_stack(),
                redirect_https: r.redirect_https,
            })
        })
        .collect();
    Ok(Runtime {
        table: HostTable::new(routes)?,
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
