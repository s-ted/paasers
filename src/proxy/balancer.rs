//! Weighted random selection among healthy upstreams.
use super::health::{HealthRegistry, UpstreamHealth};
use crate::config::UpstreamCfg;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct Upstream {
    pub addr: SocketAddr,
    pub weight: u32,
    pub health: Arc<UpstreamHealth>,
}

pub struct Balancer {
    pub upstreams: Vec<Upstream>,
}

impl Balancer {
    pub fn new(cfg: &[UpstreamCfg], registry: &HealthRegistry) -> Self {
        let upstreams = cfg
            .iter()
            .map(|u| Upstream {
                addr: u.addr,
                weight: u.weight,
                health: registry.get_or_create(u.addr),
            })
            .collect();
        Self { upstreams }
    }

    fn candidates(&self, exclude: Option<SocketAddr>) -> impl Iterator<Item = &Upstream> {
        self.upstreams
            .iter()
            .filter(move |u| u.weight > 0 && u.health.is_healthy() && Some(u.addr) != exclude)
    }

    fn choose(&self, exclude: Option<SocketAddr>) -> Option<&Upstream> {
        let total: u64 = self.candidates(exclude).map(|u| u64::from(u.weight)).sum();
        if total == 0 {
            return None;
        }
        let mut r = rand::random_range(0..total);
        self.candidates(exclude).find(|u| {
            let w = u64::from(u.weight);
            if r < w {
                true
            } else {
                r -= w;
                false
            }
        })
    }

    pub fn pick(&self) -> Option<&Upstream> {
        self.choose(None)
    }

    /// Same as `pick`, skipping one address (retry after a connect error).
    pub fn pick_excluding(&self, addr: SocketAddr) -> Option<&Upstream> {
        self.choose(Some(addr))
    }

    pub fn healthy_count(&self) -> usize {
        self.upstreams.iter().filter(|u| u.health.is_healthy()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn balancer(spec: &[(u16, u32)]) -> (Balancer, HealthRegistry) {
        let reg = HealthRegistry::new();
        let cfg: Vec<UpstreamCfg> = spec
            .iter()
            .map(|(p, w)| UpstreamCfg {
                addr: SocketAddr::from(([127, 0, 0, 1], *p)),
                weight: *w,
            })
            .collect();
        (Balancer::new(&cfg, &reg), reg)
    }

    #[test]
    fn weighted_distribution_90_10() {
        let (b, _r) = balancer(&[(1, 90), (2, 10)]);
        let first = (0..100_000)
            .filter(|_| b.pick().is_some_and(|u| u.addr.port() == 1))
            .count();
        let share = first as f64 / 100_000.0;
        assert!((0.88..=0.92).contains(&share), "share {share}");
    }

    #[test]
    fn skips_unhealthy_and_zero_weight() {
        let (b, _r) = balancer(&[(1, 5), (2, 0), (3, 5)]);
        b.upstreams[0].health.report_failure_passive();
        for _ in 0..200 {
            assert_eq!(b.pick().unwrap().addr.port(), 3);
        }
    }

    #[test]
    fn none_when_all_unhealthy() {
        let (b, _r) = balancer(&[(1, 1), (2, 1)]);
        b.upstreams.iter().for_each(|u| u.health.report_failure_passive());
        assert!(b.pick().is_none());
        assert_eq!(b.healthy_count(), 0);
    }

    #[test]
    fn pick_excluding_skips_address() {
        let (b, _r) = balancer(&[(1, 1), (2, 1)]);
        let a1 = SocketAddr::from(([127, 0, 0, 1], 1));
        for _ in 0..100 {
            assert_eq!(b.pick_excluding(a1).unwrap().addr.port(), 2);
        }
        let (single, _r2) = balancer(&[(1, 1)]);
        assert!(single.pick_excluding(a1).is_none());
    }
}
