//! Per-route client IP allowlist (`allow-ips`, plans/15).
use super::util::reject;
use crate::prelude::{BoxFut, ClientIp, Req, Resp, RouteSvc};
use http::StatusCode;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::Service;

/// Disjoint networks sorted by address, one vector per family.
#[derive(Debug, Default)]
pub struct IpAllow {
    v4: Vec<Ipv4Net>,
    v6: Vec<Ipv6Net>,
}

/// Among disjoint sorted networks, only the last one starting at or before `ip` can contain it.
fn hit<N: Copy, A: Ord + Copy>(
    nets: &[N],
    ip: A,
    start: impl Fn(N) -> A,
    has: impl Fn(N, A) -> bool,
) -> bool {
    let i = nets.partition_point(|n| start(*n) <= ip);
    i.checked_sub(1)
        .and_then(|i| nets.get(i))
        .is_some_and(|n| has(*n, ip))
}

impl IpAllow {
    /// `nets` is aggregated again here, so any input gives disjoint sorted ranges.
    pub fn from_nets(nets: &[IpNet]) -> Self {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for n in IpNet::aggregate(&nets.to_vec()) {
            match n {
                IpNet::V4(n) => v4.push(n),
                IpNet::V6(n) => v6.push(n),
            }
        }
        v4.sort_unstable_by_key(|n| n.network());
        v6.sort_unstable_by_key(|n| n.network());
        Self { v4, v6 }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(a) => hit(&self.v4, a, |n| n.network(), |n, a| n.contains(&a)),
            IpAddr::V6(a) => hit(&self.v6, a, |n| n.network(), |n, a| n.contains(&a)),
        }
    }
}

#[derive(Clone)]
pub struct IpAllowLayer {
    allow: Arc<IpAllow>,
}

impl IpAllowLayer {
    pub fn new(nets: &[IpNet]) -> Self {
        Self {
            allow: Arc::new(IpAllow::from_nets(nets)),
        }
    }
}

impl tower::Layer<RouteSvc> for IpAllowLayer {
    type Service = IpAllowSvc;
    fn layer(&self, inner: RouteSvc) -> IpAllowSvc {
        IpAllowSvc {
            inner,
            allow: self.allow.clone(),
        }
    }
}

#[derive(Clone)]
pub struct IpAllowSvc {
    inner: RouteSvc,
    allow: Arc<IpAllow>,
}

impl Service<Req> for IpAllowSvc {
    type Response = Resp;
    type Error = Infallible;
    type Future = BoxFut;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Req) -> BoxFut {
        // Fail closed: without a client address the request cannot be proven allowed.
        let ok = req
            .extensions()
            .get::<ClientIp>()
            .is_some_and(|ip| self.allow.contains(ip.0));
        if !ok {
            return Box::pin(std::future::ready(Ok(reject(
                StatusCode::FORBIDDEN,
                &req,
                "ip_blocked",
            ))));
        }
        self.inner.call(req)
    }
}
