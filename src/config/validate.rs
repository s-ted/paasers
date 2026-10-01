//! Cross-node validation of a parsed configuration.
use super::error::ConfigError;
use super::model::*;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
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

fn check_tls_files(cert: &Path, key: &Path) -> Result<(), ConfigError> {
    let certs = CertificateDer::pem_file_iter(cert)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .or_else(|e| sem(format!("cert-file {}: {e}", cert.display())))?;
    if certs.is_empty() {
        return sem(format!("cert-file {}: no certificate found", cert.display()));
    }
    PrivateKeyDer::from_pem_file(key)
        .map(|_| ())
        .or_else(|e| sem(format!("key-file {}: {e}", key.display())))
}

fn check_route(gw: &GatewayCfg, r: &RouteCfg) -> Result<(), ConfigError> {
    let id = &r.id;
    if r.tls.is_some() && gw.listen_https.is_none() {
        return sem(format!(
            "route {id}: `tls` requires an HTTPS listener (second `listen` argument)"
        ));
    }
    match &r.tls {
        Some(TlsCfg::Acme { .. }) if r.hosts.iter().any(|h| h.starts_with("*.")) => {
            return sem(format!(
                "route {id}: wildcard hosts cannot use ACME, provide cert-file/key-file"
            ));
        }
        Some(TlsCfg::Files { cert, key }) => check_tls_files(cert, key)?,
        _ => {}
    }
    if r.upstreams.iter().map(|u| u64::from(u.weight)).sum::<u64>() == 0 {
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
    if r.gatekeeper.as_ref().is_some_and(|g| g.passkey) && r.tls.is_none() {
        return sem(format!("route {id}: gatekeeper passkey requires `tls`"));
    }
    Ok(())
}

pub fn validate(cfg: &Config) -> Result<(), ConfigError> {
    let gw = &cfg.gateway;
    if gw.listen_https == Some(gw.listen_http) {
        return sem("listen: HTTP and HTTPS addresses must differ");
    }
    if let Some(m) = &cfg.mcp
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
    for (i, r) in cfg.routes.iter().enumerate() {
        for h in &r.hosts {
            if let Some(o) = cfg.routes.iter().take(i).find(|o| o.hosts.contains(h)) {
                return sem(format!(
                    "host `{h}` is declared in both route {} and route {}",
                    o.id, r.id
                ));
            }
        }
        check_route(gw, r)?;
    }
    if let Some(dc) = &gw.default_cert
        && !cfg.routes.iter().any(|r| r.tls.is_some() && r.hosts.contains(dc))
    {
        return sem(format!("default-cert `{dc}` is not a host of a route with `tls`"));
    }
    Ok(())
}
