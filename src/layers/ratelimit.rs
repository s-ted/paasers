//! Per-IP rate limiting with a global limit and path-prefix overrides.
use super::util::reject;
use crate::config::RateLimitCfg;
use crate::prelude::{BoxFut, ClientIp, Req, Resp, RouteSvc};
use governor::clock::{Clock, DefaultClock};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use http::{HeaderValue, StatusCode, header};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use tower::Service;

type Limiter = Arc<DefaultKeyedRateLimiter<IpAddr>>;
/// Route id and optional path prefix.
type LimiterKey = (Arc<str>, Option<String>);

/// Limiters live outside the runtime snapshot, so counters survive a reload with an identical config.
#[derive(Default)]
pub struct LimiterRegistry {
    inner: Mutex<HashMap<LimiterKey, (RateLimitCfg, Limiter)>>,
}

pub fn quota(c: &RateLimitCfg) -> Option<Quota> {
    Some(Quota::per_second(NonZeroU32::new(c.rps)?).allow_burst(NonZeroU32::new(c.burst)?))
}

impl LimiterRegistry {
    pub fn get_or_create(&self, route: &Arc<str>, cfg: &RateLimitCfg) -> Option<Limiter> {
        let key = (route.clone(), cfg.path.clone());
        let mut m = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((c, l)) = m.get(&key)
            && c == cfg
        {
            return Some(l.clone());
        }
        let l: Limiter = Arc::new(RateLimiter::keyed(quota(cfg)?));
        m.insert(key, (cfg.clone(), l.clone()));
        Some(l)
    }

    pub fn retain_routes(&self, active: &std::collections::HashSet<Arc<str>>) {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(r, _), _| active.contains(r));
    }

    /// Memory maintenance (R9): forget IPs whose budget is full again.
    pub fn purge(&self) {
        for (_, l) in self.inner.lock().unwrap_or_else(PoisonError::into_inner).values() {
            l.retain_recent();
            l.shrink_to_fit();
        }
    }
}

#[derive(Clone)]
pub struct RateLimitLayer {
    /// Sorted by decreasing prefix length, so the first match is the most specific.
    prefixed: Arc<Vec<(String, Limiter)>>,
    global: Option<Limiter>,
}

impl RateLimitLayer {
    pub fn new(route: &Arc<str>, cfgs: &[RateLimitCfg], reg: &LimiterRegistry) -> Option<Self> {
        let mut prefixed = Vec::new();
        let mut global = None;
        for c in cfgs {
            let l = reg.get_or_create(route, c)?;
            match &c.path {
                Some(p) => prefixed.push((p.clone(), l)),
                None => global = Some(l),
            }
        }
        prefixed.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        Some(Self {
            prefixed: Arc::new(prefixed),
            global,
        })
    }
}

impl tower::Layer<RouteSvc> for RateLimitLayer {
    type Service = RateLimit;
    fn layer(&self, inner: RouteSvc) -> RateLimit {
        RateLimit {
            inner,
            cfg: self.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RateLimit {
    inner: RouteSvc,
    cfg: RateLimitLayer,
}

/// `Err(retry_after_secs)`: the most specific prefix limiter and the global one both apply.
fn check(cfg: &RateLimitLayer, path: &str, ip: IpAddr) -> Result<(), u64> {
    let clock = DefaultClock::default();
    let secs = |n: governor::NotUntil<_>| (n.wait_time_from(clock.now()).as_secs_f64().ceil() as u64).max(1);
    if let Some((_, l)) = cfg.prefixed.iter().find(|(p, _)| path.starts_with(p.as_str())) {
        l.check_key(&ip).map_err(secs)?;
    }
    match &cfg.global {
        Some(l) => l.check_key(&ip).map_err(secs),
        None => Ok(()),
    }
}

impl Service<Req> for RateLimit {
    type Response = Resp;
    type Error = Infallible;
    type Future = BoxFut;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Req) -> BoxFut {
        let ip = req.extensions().get::<ClientIp>().map(|c| c.0);
        if let Some(ip) = ip
            && let Err(secs) = check(&self.cfg, req.uri().path(), ip)
        {
            let mut r = reject(StatusCode::TOO_MANY_REQUESTS, &req, "rate_limited");
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                r.headers_mut().insert(header::RETRY_AFTER, v);
            }
            return Box::pin(std::future::ready(Ok(r)));
        }
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move { Ok(crate::cache::layer::call_svc(&mut inner, req).await) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::empty;
    use tower::Layer;

    fn svc(cfgs: &[RateLimitCfg]) -> RateLimit {
        let inner = RouteSvc::new(tower::service_fn(|_r: Req| async {
            Ok::<_, Infallible>(http::Response::new(empty()))
        }));
        let l = RateLimitLayer::new(&Arc::from("r"), cfgs, &LimiterRegistry::default()).unwrap();
        l.layer(inner)
    }

    fn rl(rps: u32, burst: u32, path: Option<&str>) -> RateLimitCfg {
        RateLimitCfg {
            rps,
            burst,
            path: path.map(str::to_string),
        }
    }

    async fn hit(s: &mut RateLimit, ip: &str, path: &str) -> Resp {
        let mut r = http::Request::new(empty());
        *r.uri_mut() = path.parse().unwrap();
        r.extensions_mut().insert(ClientIp(ip.parse().unwrap()));
        s.call(r).await.unwrap()
    }

    #[tokio::test]
    async fn allows_burst_then_429() {
        let mut s = svc(&[rl(1, 2, None)]);
        assert_eq!(hit(&mut s, "1.1.1.1", "/").await.status(), 200);
        assert_eq!(hit(&mut s, "1.1.1.1", "/").await.status(), 200);
        let r = hit(&mut s, "1.1.1.1", "/").await;
        assert_eq!(r.status(), 429);
        assert_eq!(r.headers()[header::RETRY_AFTER], "1");
        assert_eq!(
            r.extensions().get::<crate::prelude::IncidentKind>().unwrap().0,
            "rate_limited"
        );
    }

    #[tokio::test]
    async fn per_ip_isolated() {
        let mut s = svc(&[rl(1, 1, None)]);
        assert_eq!(hit(&mut s, "1.1.1.1", "/").await.status(), 200);
        assert_eq!(hit(&mut s, "1.1.1.1", "/").await.status(), 429);
        assert_eq!(hit(&mut s, "2.2.2.2", "/").await.status(), 200);
    }

    #[tokio::test]
    async fn path_prefix_more_specific() {
        let mut s = svc(&[
            rl(100, 100, None),
            rl(1, 1, Some("/api")),
            rl(1, 3, Some("/api/login")),
        ]);
        assert_eq!(hit(&mut s, "1.1.1.1", "/api/login").await.status(), 200);
        assert_eq!(
            hit(&mut s, "1.1.1.1", "/api/login").await.status(),
            200,
            "burst 3 of the longest prefix"
        );
        assert_eq!(hit(&mut s, "1.1.1.1", "/api/other").await.status(), 200);
        assert_eq!(
            hit(&mut s, "1.1.1.1", "/api/other").await.status(),
            429,
            "/api has burst 1"
        );
        assert_eq!(
            hit(&mut s, "1.1.1.1", "/home").await.status(),
            200,
            "only the global limiter"
        );
    }

    #[tokio::test]
    async fn global_and_prefix_both_apply() {
        let mut s = svc(&[rl(1, 2, None), rl(100, 100, Some("/api"))]);
        assert_eq!(hit(&mut s, "1.1.1.1", "/api").await.status(), 200);
        assert_eq!(hit(&mut s, "1.1.1.1", "/api").await.status(), 200);
        assert_eq!(
            hit(&mut s, "1.1.1.1", "/api").await.status(),
            429,
            "global budget exhausted"
        );
    }

    #[test]
    fn registry_reuses_until_config_changes() {
        let reg = LimiterRegistry::default();
        let r: Arc<str> = Arc::from("r");
        let a = reg.get_or_create(&r, &rl(5, 5, None)).unwrap();
        assert!(Arc::ptr_eq(&a, &reg.get_or_create(&r, &rl(5, 5, None)).unwrap()));
        assert!(!Arc::ptr_eq(&a, &reg.get_or_create(&r, &rl(6, 5, None)).unwrap()));
        assert!(reg.get_or_create(&r, &rl(0, 5, None)).is_none());
        reg.purge();
        reg.retain_routes(&Default::default());
    }
}
