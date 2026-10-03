//! Cross-node validation of a parsed configuration.
use super::error::ConfigError;
use super::model::*;
use std::net::IpAddr;
use std::path::Path;

fn sem<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Semantic(msg.into()))
}

fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v) => {
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || (v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v) => {
            v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn readable(path: &Path, what: &str) -> Result<(), ConfigError> {
    std::fs::File::open(path)
        .map(|_| ())
        .or_else(|e| sem(format!("{what} {}: cannot read: {e}", path.display())))
}

fn local_index(gw: &GatewayCfg) -> crate::tls::local::LocalIndex {
    gw.certs_dir
        .as_deref()
        .map(crate::tls::local::LocalIndex::load)
        .unwrap_or_default()
}

fn acme_impossible_reason(gw: &GatewayCfg, r: &RouteCfg) -> &'static str {
    if r.hosts.iter().any(|h| h.starts_with("*.")) {
        "wildcard hosts cannot use HTTP-01"
    } else if gw.default_email.is_none() {
        "no email, set `tls email=` or gateway `default-email`"
    } else {
        "ACME is not available"
    }
}

/// Auto mode without ACME needs a local certificate for every host.
fn check_tls_sources(
    gw: &GatewayCfg,
    r: &RouteCfg,
    idx: &crate::tls::local::LocalIndex,
) -> Result<(), ConfigError> {
    if let Some(TlsCfg {
        mode: TlsMode::Auto { acme: None },
    }) = &r.tls
        && let Some(h) = r.hosts.iter().find(|h| idx.best_any(h).is_none())
    {
        return sem(format!(
            "route {}: host {h} has no local certificate and ACME is impossible ({})",
            r.id,
            acme_impossible_reason(gw, r)
        ));
    }
    Ok(())
}

/// Non fatal findings, printed by `paasers check` and logged at startup.
pub fn warnings(cfg: &Config) -> Vec<String> {
    let idx = local_index(&cfg.gateway);
    let mut out = Vec::new();
    for r in &cfg.routes {
        if let Some(TlsCfg {
            mode: TlsMode::Auto { acme: None },
        }) = &r.tls
        {
            for h in r.hosts.iter().filter_map(|h| idx.best_any(h).map(|c| (h, c))) {
                let when = humantime::format_rfc3339_seconds(
                    std::time::UNIX_EPOCH
                        + std::time::Duration::from_secs(h.1.not_after.max(0).unsigned_abs()),
                );
                out.push(format!(
                    "no ACME fallback for {}: renew the local certificate before {when}",
                    h.0
                ));
            }
        }
    }
    out
}

fn check_route(
    gw: &GatewayCfg,
    r: &RouteCfg,
    idx: &crate::tls::local::LocalIndex,
) -> Result<(), ConfigError> {
    let id = &r.id;
    if r.tls.is_some() && gw.listen_https.is_none() {
        return sem(format!(
            "route {id}: `tls` requires an HTTPS listener (second `listen` argument)"
        ));
    }
    check_tls_sources(gw, r, idx)?;
    if let Some(s) = &r.static_files
        && !s.root.is_dir()
    {
        return sem(format!(
            "route {id}: static {}: not a directory",
            s.root.display()
        ));
    }
    if r.static_files.is_none() && r.upstreams.iter().map(|u| u64::from(u.weight)).sum::<u64>() == 0 {
        return sem(format!("route {id}: the sum of upstream weights must be > 0"));
    }
    for (i, u) in r.upstreams.iter().enumerate() {
        if r.upstreams.iter().skip(i + 1).any(|o| o.addr == u.addr) {
            return sem(format!("route {id}: duplicate upstream {}", u.addr));
        }
        if !is_private(u.addr.ip()) {
            tracing::warn!(route = %id, upstream = %u.addr, "upstream address is not a private address");
        }
    }
    if r.health.timeout >= r.health.interval {
        return sem(format!(
            "route {id}: health-check timeout must be lower than interval"
        ));
    }
    let globals = r.rate_limits.iter().filter(|l| l.path.is_none()).count();
    if globals > 1 {
        return sem(format!("route {id}: at most one rate-limit without `path`"));
    }
    for (i, l) in r.rate_limits.iter().enumerate() {
        if l.path.is_some() && r.rate_limits.iter().skip(i + 1).any(|o| o.path == l.path) {
            return sem(format!("route {id}: duplicate rate-limit path"));
        }
    }
    if let Some(g) = &r.geoip {
        maxminddb::Reader::open_readfile(&g.database).or_else(|e| {
            sem(format!(
                "route {id}: geoip database {}: {e}",
                g.database.display()
            ))
        })?;
    }
    Ok(())
}

pub fn validate(cfg: &Config) -> Result<(), ConfigError> {
    let gw = &cfg.gateway;
    if gw.listen_http.port() != 0 && gw.listen_https == Some(gw.listen_http) {
        return sem("listen: HTTP and HTTPS addresses must differ");
    }
    if let Some(m) = &cfg.mcp
        && !m.implicit
        && m.listen.port() != 0
        && (m.listen == gw.listen_http || Some(m.listen) == gw.listen_https)
    {
        return sem("mcp-server listen address conflicts with gateway listen");
    }
    let l = &gw.limits;
    if !(8 * 1024..=1024 * 1024).contains(&l.max_headers_size) {
        return sem("limits max-headers-size must be between 8KiB and 1MiB");
    }
    if l.max_connections < 1 || l.max_body < 1024 || l.header_read_timeout.as_secs() < 1 {
        return sem("limits: max-connections >= 1, max-body >= 1KiB, header-read-timeout >= 1s required");
    }
    if let Some(p) = &gw.acme_ca_root {
        readable(p, "acme-ca-root")?;
    }
    if let Some(d) = &gw.certs_dir
        && !d.is_dir()
    {
        return sem(format!("certs-dir {}: not a readable directory", d.display()));
    }
    let idx = local_index(gw);
    for (i, r) in cfg.routes.iter().enumerate() {
        for h in &r.hosts {
            if let Some(o) = cfg.routes.iter().take(i).find(|o| o.hosts.contains(h)) {
                return sem(format!(
                    "host `{h}` is declared in both route {} and route {}",
                    o.id, r.id
                ));
            }
        }
        check_route(gw, r, &idx)?;
    }
    if let Some(dc) = &gw.default_cert
        && !cfg.routes.iter().any(|r| r.tls.is_some() && r.hosts.contains(dc))
    {
        return sem(format!("default-cert `{dc}` is not a host of a route with `tls`"));
    }
    Ok(())
}
