//! Runtime snapshot and host lookup (minimal version, completed in P4).
use crate::config::{Config, Limits, RouteCfg};
use crate::prelude::{Req, Resp, RouteSvc, simple};
use crate::server::Shared;
use ipnet::IpNet;
use std::collections::HashMap;
use std::convert::Infallible;
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

#[derive(Default)]
pub struct HostTable {
    exact: HashMap<String, Arc<RouteRuntime>>,
    wildcard: HashMap<String, Arc<RouteRuntime>>,
}

impl HostTable {
    /// Exact host first, then a single-label wildcard (`*.example.com`).
    pub fn lookup(&self, host: &str) -> Option<&Arc<RouteRuntime>> {
        self.exact
            .get(host)
            .or_else(|| host.split_once('.').and_then(|(_, rest)| self.wildcard.get(rest)))
    }
}

pub struct Runtime {
    pub table: HostTable,
    pub trusted_proxies: Vec<IpNet>,
    pub https_port: Option<u16>,
    pub limits: Limits,
    pub generation: u64,
    pub config: Arc<Config>,
}

/// Placeholder data plane until the proxy exists (P5).
fn placeholder_service() -> RouteSvc {
    let svc = tower::service_fn(|_req: Req| async {
        Ok::<Resp, Infallible>(simple(
            http::StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            "not wired",
        ))
    });
    RouteSvc::new(svc)
}

pub fn build(cfg: &Arc<Config>, shared: &Shared) -> Result<Runtime, BuildError> {
    let mut table = HostTable::default();
    for r in &cfg.routes {
        let rt = Arc::new(RouteRuntime {
            id: r.id.clone(),
            hosts: r.hosts.clone(),
            cfg: Arc::new(r.clone()),
            service: placeholder_service(),
            redirect_https: r.redirect_https,
        });
        for h in &r.hosts {
            let (map, key) = match h.strip_prefix("*.") {
                Some(rest) => (&mut table.wildcard, rest.to_string()),
                None => (&mut table.exact, h.clone()),
            };
            if map.insert(key, rt.clone()).is_some() {
                return Err(BuildError::Router(format!("duplicate host `{h}`")));
            }
        }
    }
    Ok(Runtime {
        table,
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
    fn lookup_exact_wildcard_and_unknown() {
        let c = cfg("route \"a.com\" \"*.b.com\" { upstream \"10.0.0.1:80\" }");
        let rt = build(&c, &Shared::new()).unwrap();
        assert!(rt.table.lookup("a.com").is_some());
        assert!(rt.table.lookup("x.b.com").is_some());
        assert!(rt.table.lookup("x.y.b.com").is_none());
        assert!(rt.table.lookup("b.com").is_none());
        assert!(rt.table.lookup("nope.com").is_none());
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
