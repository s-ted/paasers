//! Host table: a radix tree over reversed DNS labels.
use super::{BuildError, RouteRuntime, host::host_key};
use std::sync::Arc;

#[derive(Default)]
pub struct HostTable {
    router: matchit::Router<usize>,
    routes: Vec<Arc<RouteRuntime>>,
}

impl HostTable {
    pub fn new(routes: Vec<Arc<RouteRuntime>>) -> Result<Self, BuildError> {
        let mut router = matchit::Router::new();
        for (idx, r) in routes.iter().enumerate() {
            for h in &r.hosts {
                router
                    .insert(host_key(h), idx)
                    .map_err(|e| BuildError::Router(format!("host `{h}`: {e}")))?;
            }
        }
        Ok(Self { router, routes })
    }

    /// `host` must be normalized and contain only `[a-z0-9.-]` (the entry service guarantees it).
    pub fn lookup(&self, host: &str) -> Option<&Arc<RouteRuntime>> {
        let key = host_key(host);
        self.router.at(&key).ok().and_then(|m| self.routes.get(*m.value))
    }

    pub fn routes(&self) -> &[Arc<RouteRuntime>] {
        &self.routes
    }
}

#[cfg(test)]
mod tests {
    use super::super::stack::placeholder_service;
    use super::*;
    use crate::config::parse_str;
    use crate::proxy::{Balancer, HealthRegistry};

    fn table(src: &str) -> HostTable {
        let cfg = parse_str(src, &|_| None).unwrap();
        let routes = cfg
            .routes
            .iter()
            .map(|r| {
                Arc::new(RouteRuntime {
                    id: r.id.clone(),
                    hosts: r.hosts.clone(),
                    cfg: Arc::new(r.clone()),
                    service: placeholder_service(),
                    balancer: Arc::new(Balancer::new(&r.upstreams, &HealthRegistry::new())),
                    redirect_https: r.redirect_https,
                })
            })
            .collect();
        HostTable::new(routes).unwrap()
    }

    const SRC: &str = "route \"www.client.com\" { upstream \"10.0.0.1:80\" }\nroute \"*.client.com\" { upstream \"10.0.0.2:80\" }";

    #[test]
    fn exact_beats_wildcard() {
        let t = table(SRC);
        assert_eq!(&*t.lookup("www.client.com").unwrap().id, "www.client.com");
        assert_eq!(&*t.lookup("dev.client.com").unwrap().id, "*.client.com");
    }

    #[test]
    fn wildcard_single_label_only() {
        assert!(table(SRC).lookup("a.b.client.com").is_none());
    }

    #[test]
    fn apex_not_matched_by_wildcard() {
        assert!(table(SRC).lookup("client.com").is_none());
    }

    #[test]
    fn unknown_none() {
        assert!(table(SRC).lookup("other.org").is_none());
        assert!(table(SRC).lookup("com").is_none());
    }
}
