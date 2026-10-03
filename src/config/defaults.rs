//! Built-in defaults of features that are on without any configuration node.
//! Each one has an explicit opt-out (`mcp-server off`, `transform off`, `cache off`, `rate-limit off`,
//! `trusted-proxies` with no argument).
use super::model::*;
use super::model_auth::*;
use ipnet::IpNet;
use std::net::SocketAddr;
use std::time::Duration;

/// Private ranges (RFC 1918, ULA): the usual addresses of a front load balancer. Loopback is not
/// included, a local process must opt in.
pub fn trusted_proxies() -> Vec<IpNet> {
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// Local-only MCP server, no token (loopback is enforced by the parser for token-less servers).
pub fn mcp() -> McpCfg {
    McpCfg {
        listen: SocketAddr::from(([127, 0, 0, 1], 9090)),
        token: None,
        implicit: true,
    }
}

/// Generous per client IP limit: it stops abuse, not normal traffic.
pub fn rate_limit() -> RateLimitCfg {
    RateLimitCfg {
        rps: 100,
        burst: 200,
        path: None,
    }
}

fn op(header: &str, op: OpKind) -> HeaderOpCfg {
    HeaderOpCfg {
        header: header.into(),
        op,
    }
}

/// Response hardening. Values chosen by the backend are kept. No HSTS: it is hard to undo in a
/// browser, so it stays an explicit `transform` choice.
pub fn security_transform() -> TransformCfg {
    TransformCfg {
        request: Vec::new(),
        response: vec![
            op("x-content-type-options", OpKind::SetIfAbsent("nosniff".into())),
            op("server", OpKind::Remove),
            op("x-powered-by", OpKind::Remove),
        ],
        status: Vec::new(),
    }
}

/// Defaults first, then the user's operations (they can override or remove what the defaults did).
pub fn merge_transform(mut base: TransformCfg, user: TransformCfg) -> TransformCfg {
    base.request.extend(user.request);
    base.response.extend(user.response);
    base.status = user.status;
    base
}

impl Default for CacheCfg {
    /// The backend drives the cache through `Cache-Control` (`default-ttl` is 0).
    fn default() -> Self {
        Self {
            max_size: 64 * 1024 * 1024,
            stale_while_revalidate: Duration::ZERO,
            stale_if_error: Duration::ZERO,
            default_ttl: Duration::ZERO,
            max_object_size: 8 * 1024 * 1024,
        }
    }
}
