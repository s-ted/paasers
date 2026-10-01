//! Parsing of `route` and its simple children.
use super::error::ConfigError;
use super::kdl_ext::{Env, NodeCtx};
use super::model::*;
use super::{parse_features as feat, parse_gate, units};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const ROUTE_NODES: &[&str] = &[
    "upstream",
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
];

pub fn parse_route(n: &NodeCtx<'_>, gw: &GatewayCfg, env: Env<'_>) -> Result<RouteCfg, ConfigError> {
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
    if upstreams.is_empty() {
        return Err(n.err("route needs at least one upstream"));
    }
    let tls = scope.single("tls")?.map(|t| parse_tls(&t, gw)).transpose()?;
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
    Ok(RouteCfg {
        id,
        hosts,
        redirect_https,
        upstreams,
        health: scope
            .single("health-check")?
            .map(|h| parse_health(&h))
            .transpose()?
            .unwrap_or_default(),
        request_timeout,
        cache: scope
            .single("cache")?
            .map(|c| feat::parse_cache(&c))
            .transpose()?,
        compression: scope
            .single("compression")?
            .map(|c| feat::parse_compression(&c))
            .transpose()?,
        geoip: scope
            .single("geoip")?
            .map(|c| feat::parse_geoip(&c))
            .transpose()?,
        rate_limits: scope
            .all("rate-limit")
            .iter()
            .map(feat::parse_rate_limit)
            .collect::<Result<_, _>>()?,
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
        transform: scope
            .single("transform")?
            .map(|t| super::parse_transform::parse_transform(&t))
            .transpose()?,
        fallback: scope
            .single("fallback")?
            .map(|f| parse_fallback(&f))
            .transpose()?
            .unwrap_or_default(),
        tls,
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

fn parse_tls(n: &NodeCtx<'_>, gw: &GatewayCfg) -> Result<TlsCfg, ConfigError> {
    n.check_args(0, 0)?;
    n.check_props(&["email", "cert-file", "key-file"])?;
    match (n.prop_str("cert-file")?, n.prop_str("key-file")?) {
        (Some(c), Some(k)) => {
            if n.prop("email").is_some() {
                return Err(n.err("tls: `email` cannot be combined with cert-file/key-file"));
            }
            Ok(TlsCfg::Files {
                cert: PathBuf::from(c),
                key: PathBuf::from(k),
            })
        }
        (None, None) => {
            let email = n
                .prop_str("email")?
                .map(str::to_string)
                .or_else(|| gw.default_email.clone());
            email
                .map(|email| TlsCfg::Acme { email })
                .ok_or_else(|| n.err("tls requires `email` or gateway `default-email`"))
        }
        _ => Err(n.err("tls: cert-file and key-file must be given together")),
    }
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

fn parse_fallback(n: &NodeCtx<'_>) -> Result<FallbackCfg, ConfigError> {
    n.check_args(0, 0)?;
    n.check_props(&["status", "show-incident-id", "title", "message", "on"])?;
    let d = FallbackCfg::default();
    let status: u16 = n.prop_num("status")?.unwrap_or(d.status);
    if !(500..=599).contains(&status) {
        return Err(n.err("fallback status must be in 500..=599"));
    }
    let on = match n.prop_str("on")? {
        Some(s) => s
            .split(',')
            .map(|p| {
                p.trim()
                    .parse::<u16>()
                    .map_err(|_| n.err(format!("invalid status `{p}` in `on`")))
            })
            .collect::<Result<_, _>>()?,
        None => d.on,
    };
    Ok(FallbackCfg {
        status,
        show_incident_id: n.prop_bool("show-incident-id")?.unwrap_or(true),
        title: n.prop_str("title")?.map_or(d.title, str::to_string),
        message: n.prop_str("message")?.map_or(d.message, str::to_string),
        on,
    })
}
