//! Parsing of `route` and its simple children.
use super::error::ConfigError;
use super::kdl_ext::{Env, NodeCtx};
use super::model::*;
use super::{defaults, parse_features as feat, parse_gate, units};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const ROUTE_NODES: &[&str] = &[
    "upstream",
    "static",
    "health-check",
    "timeouts",
    "tls",
    "fallback",
    "cache",
    "compression",
    "geoip",
    "rate-limit",
    "gatekeeper",
    "jwt-validation",
    "api-keys",
    "transform",
    "redirect-https",
    "retry",
    "allow-ips",
];

pub fn parse_route(
    n: &NodeCtx<'_>,
    gw: &GatewayCfg,
    sets: &super::parse_ipset::IpSets,
    env: Env<'_>,
) -> Result<RouteCfg, ConfigError> {
    n.check_props(&[])?;
    n.check_args(1, usize::MAX)?;
    let hosts: Vec<String> = n
        .args_str()?
        .into_iter()
        .map(|h| units::normalize_host(h).map_err(|m| n.err(m)))
        .collect::<Result<_, _>>()?;
    let id: Arc<str> = hosts
        .first()
        .map(|h| Arc::from(h.as_str()))
        .ok_or_else(|| n.err("route needs a host"))?;
    let scope = n.scope();
    scope.check_only(ROUTE_NODES)?;
    for name in ROUTE_NODES
        .iter()
        .filter(|x| **x != "upstream" && **x != "rate-limit")
    {
        scope.single(name)?;
    }
    let upstreams: Vec<UpstreamCfg> = scope
        .all("upstream")
        .iter()
        .map(parse_upstream)
        .collect::<Result<_, _>>()?;
    let explicit = scope.single("static")?.map(|s| parse_static(&s)).transpose()?;
    if explicit.is_some() && !upstreams.is_empty() {
        return Err(n.err("static and upstream are mutually exclusive"));
    }
    // No upstream and no `static`: the route serves the current directory.
    let static_files = match explicit {
        None if upstreams.is_empty() => Some(StaticCfg::default()),
        other => other,
    };
    if static_files.is_some()
        && let Some((name, bad)) = ["health-check", "timeouts", "cache", "fallback", "retry"]
            .into_iter()
            .find_map(|name| scope.single(name).ok().flatten().map(|b| (name, b)))
    {
        return Err(bad.err(format!("`{name}` does not apply to a static route")));
    }
    let tls = scope
        .single("tls")?
        .map(|t| super::parse_tls::parse_tls(&t, gw, &hosts))
        .transpose()?;
    let redirect_https = match scope.single("redirect-https")? {
        Some(r) => {
            r.check_args(1, 1)?;
            r.check_props(&[])?;
            r.arg_bool(0)?
        }
        None => tls.is_some(),
    };
    let request_timeout = match scope.single("timeouts")? {
        Some(t) => {
            t.check_args(0, 0)?;
            t.check_props(&["request"])?;
            let d = t.prop_dur("request")?.unwrap_or(Duration::from_secs(60));
            if d < Duration::from_millis(100) || d > Duration::from_secs(3600) {
                return Err(t.err("timeouts request must be between 100ms and 1h"));
            }
            d
        }
        None => Duration::from_secs(60),
    };
    let cache = match scope.single("cache")? {
        Some(c) => feat::parse_cache(&c)?,
        // On by default for proxied routes: the backend decides through `Cache-Control`.
        None => static_files.is_none().then(CacheCfg::default),
    };
    let transform = match scope.single("transform")? {
        Some(t) => super::parse_transform::parse_transform(&t)?
            .map(|u| defaults::merge_transform(defaults::security_transform(), u)),
        None => Some(defaults::security_transform()),
    };
    let rate_limits = feat::parse_rate_limits(&scope.all("rate-limit"))?;
    let allow_ips = match scope.single("allow-ips")? {
        Some(a) => match super::parse_ipset::ip_list(&a, sets)? {
            v if v.is_empty() => return Err(a.err("allow-ips needs at least one entry")),
            v => Some(v),
        },
        None => None,
    };
    Ok(RouteCfg {
        id,
        hosts,
        redirect_https,
        upstreams,
        static_files,
        health: scope
            .single("health-check")?
            .map(|h| parse_health(&h))
            .transpose()?
            .unwrap_or_default(),
        request_timeout,
        cache,
        // Enabled by default (zstd, brotli, gzip); `compression off` disables it.
        compression: match scope.single("compression")? {
            Some(c) => feat::parse_compression(&c)?,
            None => Some(CompressionCfg::default()),
        },
        geoip: scope
            .single("geoip")?
            .map(|c| feat::parse_geoip(&c))
            .transpose()?,
        allow_ips,
        rate_limits,
        gatekeeper: scope
            .single("gatekeeper")?
            .map(|g| parse_gate::parse_gatekeeper(&g, tls.is_some(), env))
            .transpose()?,
        jwt: scope
            .single("jwt-validation")?
            .map(|j| super::parse_jwt::parse_jwt(&j, env))
            .transpose()?,
        api_keys: scope
            .single("api-keys")?
            .map(|a| feat::parse_api_keys(&a))
            .transpose()?,
        transform,
        fallback: match scope.single("fallback")? {
            Some(f) => feat::parse_fallback(&f)?,
            None => Some(FallbackCfg::default()),
        },
        retry: match scope.single("retry")? {
            Some(r) => feat::parse_retry(&r)?,
            None => true,
        },
        tls,
    })
}

fn parse_static(n: &NodeCtx<'_>) -> Result<StaticCfg, ConfigError> {
    n.check_args(1, 1)?;
    n.check_props(&[
        "index",
        "listing",
        "spa",
        "hidden",
        "follow-symlinks",
        "cache-control",
    ])?;
    n.scope().check_only(&[])?;
    let index = n.prop_str("index")?.unwrap_or("index.html");
    if index.contains('/') || index.contains('\\') || index.contains("..") {
        return Err(n.err("static index must be a plain file name"));
    }
    Ok(StaticCfg {
        root: n.arg_str(0)?.into(),
        index: index.to_string(),
        listing: n.prop_bool("listing")?.unwrap_or(true),
        spa: n.prop_bool("spa")?.unwrap_or(false),
        hidden: n.prop_bool("hidden")?.unwrap_or(false),
        follow_symlinks: n.prop_bool("follow-symlinks")?.unwrap_or(false),
        cache_control: n.prop_str("cache-control")?.map(str::to_string),
    })
}

fn parse_upstream(n: &NodeCtx<'_>) -> Result<UpstreamCfg, ConfigError> {
    n.check_args(1, 1)?;
    n.check_props(&["weight"])?;
    let addr: SocketAddr = n
        .arg_str(0)?
        .parse()
        .map_err(|_| n.err("upstream must be ip:port"))?;
    let weight: u32 = n.prop_num("weight")?.unwrap_or(1);
    if weight > 1000 {
        return Err(n.err("upstream weight must be in 0..=1000"));
    }
    Ok(UpstreamCfg { addr, weight })
}

fn parse_health(n: &NodeCtx<'_>) -> Result<HealthCfg, ConfigError> {
    n.check_args(0, 0)?;
    n.check_props(&[
        "path",
        "interval",
        "timeout",
        "unhealthy-after",
        "healthy-after",
        "mode",
        "enabled",
    ])?;
    let d = HealthCfg::default();
    let path = n.prop_str("path")?.map_or(d.path, str::to_string);
    if !path.starts_with('/') {
        return Err(n.err("health-check path must start with `/`"));
    }
    let after = |name: &str, def: u32| -> Result<u32, ConfigError> {
        let v = n.prop_num::<u32>(name)?.unwrap_or(def);
        if v < 1 {
            Err(n.err(format!("`{name}` must be >= 1")))
        } else {
            Ok(v)
        }
    };
    let mode = match n.prop_str("mode")?.unwrap_or("http") {
        "http" => HealthMode::Http,
        "tcp" => HealthMode::Tcp,
        _ => return Err(n.err("health-check mode must be \"http\" or \"tcp\"")),
    };
    let interval = n.prop_dur("interval")?.unwrap_or(d.interval);
    if interval < Duration::from_secs(1) {
        return Err(n.err("health-check interval must be >= 1s"));
    }
    Ok(HealthCfg {
        path,
        interval,
        timeout: n.prop_dur("timeout")?.unwrap_or(d.timeout),
        unhealthy_after: after("unhealthy-after", d.unhealthy_after)?,
        healthy_after: after("healthy-after", d.healthy_after)?,
        mode,
        enabled: n.prop_bool("enabled")?.unwrap_or(true),
    })
}
