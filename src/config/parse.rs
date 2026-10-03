//! Parsing of the `gateway` and `mcp-server` nodes.
use super::error::ConfigError;
use super::kdl_ext::{Env, NodeCtx};
use super::model::*;
use super::units;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

const GATEWAY_NODES: &[&str] = &[
    "listen",
    "storage-path",
    "acme-directory",
    "acme-ca-root",
    "default-email",
    "certs-dir",
    "trusted-proxies",
    "flight-recorder",
    "log",
    "limits",
    "worker-threads",
    "default-cert",
    "shutdown-grace",
];

pub fn default_gateway() -> GatewayCfg {
    GatewayCfg {
        listen_http: SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 80)),
        listen_https: Some(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 443))),
        storage_path: PathBuf::from("/var/lib/gateway/certs.db"),
        acme_directory: AcmeDirectory::Production,
        acme_ca_root: None,
        default_email: None,
        certs_dir: None,
        trusted_proxies: super::defaults::trusted_proxies(),
        flight_recorder_capacity: 500,
        log: LogCfg {
            json: false,
            level: "info".into(),
        },
        limits: Limits {
            max_connections: 10_000,
            max_body: 100 * 1024 * 1024,
            header_read_timeout: Duration::from_secs(30),
            max_headers_size: 64 * 1024,
        },
        worker_threads: None,
        default_cert: None,
        shutdown_grace: Duration::from_secs(30),
    }
}

fn listen_addr(n: &NodeCtx<'_>, s: &str) -> Result<SocketAddr, ConfigError> {
    units::parse_listen(s).map_err(|m| n.err(m))
}

fn dur_arg(n: &NodeCtx<'_>) -> Result<Duration, ConfigError> {
    units::parse_duration(n.one_str()?).map_err(|m| n.err(m))
}

pub fn parse_gateway(n: &NodeCtx<'_>) -> Result<GatewayCfg, ConfigError> {
    n.check_args(0, 0)?;
    n.check_props(&[])?;
    let scope = n.scope();
    scope.check_only(GATEWAY_NODES)?;
    let mut g = default_gateway();
    // Every child is a singleton.
    for name in GATEWAY_NODES {
        scope.single(name)?;
    }
    if let Some(c) = scope.single("listen")? {
        c.check_args(1, 2)?;
        c.check_props(&[])?;
        g.listen_http = listen_addr(&c, c.arg_str(0)?)?;
        g.listen_https = if c.args().count() == 2 {
            Some(listen_addr(&c, c.arg_str(1)?)?)
        } else {
            None
        };
    }
    if let Some(c) = scope.single("storage-path")? {
        g.storage_path = PathBuf::from(c.one_str()?);
    }
    if let Some(c) = scope.single("acme-directory")? {
        g.acme_directory = match c.one_str()? {
            "production" => AcmeDirectory::Production,
            "staging" => AcmeDirectory::Staging,
            u if u.starts_with("https://") => AcmeDirectory::Custom(u.to_string()),
            _ => return Err(c.err("acme-directory must be production, staging or an https URL")),
        };
    }
    if let Some(c) = scope.single("acme-ca-root")? {
        g.acme_ca_root = Some(PathBuf::from(c.one_str()?));
    }
    if let Some(c) = scope.single("certs-dir")? {
        g.certs_dir = Some(PathBuf::from(c.one_str()?));
    }
    if let Some(c) = scope.single("default-email")? {
        g.default_email = Some(c.one_str()?.to_string());
    }
    if let Some(c) = scope.single("trusted-proxies")? {
        c.check_props(&[])?;
        g.trusted_proxies = c
            .args_str()?
            .into_iter()
            .map(|s| units::parse_net(s).map_err(|m| c.err(m)))
            .collect::<Result<_, _>>()?;
    }
    if let Some(c) = scope.single("flight-recorder")? {
        c.check_args(0, 1)?;
        if c.args().next().is_some() {
            // `flight-recorder off`: incidents are not kept (the MCP server then has nothing to show).
            if c.arg_str(0)? != "off" {
                return Err(c.err("flight-recorder accepts only the argument `off`"));
            }
            c.check_props(&[])?;
            g.flight_recorder_capacity = 0;
        } else {
            c.check_props(&["capacity"])?;
            let cap: u32 = c.prop_num("capacity")?.unwrap_or(500);
            if !(1..=100_000).contains(&cap) {
                return Err(c.err("flight-recorder capacity must be in 1..=100000"));
            }
            g.flight_recorder_capacity = cap as usize;
        }
    }
    if let Some(c) = scope.single("log")? {
        c.check_props(&["format", "level"])?;
        g.log.json = match c.prop_str("format")?.unwrap_or("text") {
            "text" => false,
            "json" => true,
            _ => return Err(c.err("log format must be \"text\" or \"json\"")),
        };
        if let Some(l) = c.prop_str("level")? {
            g.log.level = l.to_string();
        }
    }
    if let Some(c) = scope.single("limits")? {
        c.check_props(&[
            "max-connections",
            "max-body",
            "header-read-timeout",
            "max-headers-size",
        ])?;
        let l = &mut g.limits;
        l.max_connections = c
            .prop_num::<u32>("max-connections")?
            .map_or(l.max_connections, |v| v as usize);
        l.max_body = c.prop_size("max-body")?.unwrap_or(l.max_body);
        l.header_read_timeout = c
            .prop_dur("header-read-timeout")?
            .unwrap_or(l.header_read_timeout);
        l.max_headers_size = c.prop_size("max-headers-size")?.unwrap_or(l.max_headers_size);
    }
    if let Some(c) = scope.single("worker-threads")? {
        c.check_args(1, 1)?;
        let e = c.args().next().ok_or_else(|| c.err("missing argument"))?;
        let v = match e.value() {
            kdl::KdlValue::Integer(v) => u16::try_from(*v).ok().filter(|v| *v >= 1),
            _ => None,
        };
        g.worker_threads =
            Some(usize::from(v.ok_or_else(|| {
                c.err_entry(e, "worker-threads must be 1..=65535")
            })?));
    }
    if let Some(c) = scope.single("default-cert")? {
        let h = units::normalize_host(c.one_str()?).map_err(|m| c.err(m))?;
        g.default_cert = Some(h);
    }
    if let Some(c) = scope.single("shutdown-grace")? {
        g.shutdown_grace = dur_arg(&c)?;
    }
    Ok(g)
}

/// `mcp-server off` disables the built-in server (None).
pub fn parse_mcp(n: &NodeCtx<'_>, env: Env<'_>) -> Result<Option<McpCfg>, ConfigError> {
    n.check_args(0, 1)?;
    n.check_props(&[])?;
    if n.args().next().is_some() {
        if n.arg_str(0)? != "off" {
            return Err(n.err("mcp-server accepts only the argument `off`"));
        }
        n.scope().check_only(&[])?;
        return Ok(None);
    }
    let scope = n.scope();
    scope.check_only(&["listen", "token", "token-env"])?;
    let listen = match scope.single("listen")? {
        Some(c) => listen_addr(&c, c.one_str()?)?,
        None => SocketAddr::from(([127, 0, 0, 1], 9090)),
    };
    let token = match (scope.single("token")?, scope.single("token-env")?) {
        (Some(_), Some(e)) => return Err(e.err("`token` and `token-env` are mutually exclusive")),
        (Some(t), None) => Some(t.one_str()?.to_string()),
        (None, Some(e)) => {
            let var = e.one_str()?;
            match env(var).filter(|v| !v.is_empty()) {
                Some(v) => Some(v),
                None => return Err(e.err(format!("environment variable `{var}` is missing or empty"))),
            }
        }
        (None, None) => None,
    };
    match &token {
        Some(t) if t.len() < 16 => return Err(n.err("mcp token must be at least 16 characters")),
        None if !listen.ip().is_loopback() => {
            return Err(n.err("mcp-server without token must listen on loopback"));
        }
        _ => {}
    }
    Ok(Some(McpCfg {
        listen,
        token,
        implicit: false,
    }))
}
