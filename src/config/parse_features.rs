//! Parsing of cache, compression, geoip, rate-limit, jwt, api-keys and transform nodes.
use super::error::ConfigError;
use super::kdl_ext::NodeCtx;
use super::model::*;
use super::model_auth::*;
use super::units;
use http::HeaderName;
use std::path::PathBuf;
use std::str::FromStr;

/// `cache off` disables it (None).
pub fn parse_cache(n: &NodeCtx<'_>) -> Result<Option<CacheCfg>, ConfigError> {
    n.check_args(0, 1)?;
    if n.args().next().is_some() {
        if n.arg_str(0)? != "off" {
            return Err(n.err("cache accepts only the argument `off`"));
        }
        n.check_props(&[])?;
        return Ok(None);
    }
    n.check_props(&[
        "max-size",
        "stale-while-revalidate",
        "stale-if-error",
        "default-ttl",
        "max-object-size",
    ])?;
    let max_size = n.prop_size("max-size")?.unwrap_or(64 * 1024 * 1024);
    let max_object_size = n.prop_size("max-object-size")?.unwrap_or(8 * 1024 * 1024);
    if max_object_size > max_size {
        return Err(n.err("cache max-object-size must be <= max-size"));
    }
    Ok(Some(CacheCfg {
        max_size,
        stale_while_revalidate: n.prop_dur("stale-while-revalidate")?.unwrap_or_default(),
        stale_if_error: n.prop_dur("stale-if-error")?.unwrap_or_default(),
        default_ttl: n.prop_dur("default-ttl")?.unwrap_or_default(),
        max_object_size,
    }))
}

/// `compression off` disables it (None). Otherwise Some(cfg) with defaults for absent props.
pub fn parse_compression(n: &NodeCtx<'_>) -> Result<Option<CompressionCfg>, ConfigError> {
    n.check_args(0, 1)?;
    if n.args().next().is_some() {
        if n.arg_str(0)? != "off" {
            return Err(n.err("compression accepts only the argument `off`"));
        }
        n.check_props(&[])?;
        return Ok(None);
    }
    n.check_props(&["zstd", "brotli", "gzip", "min-size"])?;
    let min_size = n.prop_size("min-size")?.unwrap_or(1024);
    if min_size > 16 * 1024 * 1024 {
        return Err(n.err("compression min-size must be <= 16MiB"));
    }
    let c = CompressionCfg {
        zstd: n.prop_bool("zstd")?.unwrap_or(true),
        brotli: n.prop_bool("brotli")?.unwrap_or(true),
        gzip: n.prop_bool("gzip")?.unwrap_or(true),
        min_size,
    };
    if !(c.zstd || c.brotli || c.gzip) {
        return Err(n.err("compression with no algorithm enabled"));
    }
    Ok(Some(c))
}

pub fn parse_geoip(n: &NodeCtx<'_>) -> Result<GeoIpCfg, ConfigError> {
    n.check_args(0, 0)?;
    n.check_props(&["database", "block-countries", "allow-countries", "inject-header"])?;
    let database = n
        .prop_str("database")?
        .ok_or_else(|| n.err("geoip requires `database`"))?;
    let list = |name: &str| -> Result<Vec<String>, ConfigError> {
        n.prop_str(name)?.map_or(Ok(Vec::new()), |s| {
            units::parse_countries(s).map_err(|m| n.err(m))
        })
    };
    let (block, allow) = (list("block-countries")?, list("allow-countries")?);
    if !block.is_empty() && !allow.is_empty() {
        return Err(n.err("block-countries and allow-countries are mutually exclusive"));
    }
    Ok(GeoIpCfg {
        database: PathBuf::from(database),
        block,
        allow,
        inject_header: n.prop_bool("inject-header")?.unwrap_or(true),
    })
}

/// All `rate-limit` nodes of a route. `rate-limit off` (alone) disables limiting. Without a global
/// rule, the generous built-in one is added.
pub fn parse_rate_limits(nodes: &[NodeCtx<'_>]) -> Result<Vec<RateLimitCfg>, ConfigError> {
    let off = |n: &NodeCtx<'_>| n.args().next().is_some();
    if let Some(o) = nodes.iter().find(|n| off(n)) {
        if o.arg_str(0)? != "off" {
            return Err(o.err("rate-limit accepts only the argument `off`"));
        }
        o.check_props(&[])?;
        if nodes.len() > 1 {
            return Err(o.err("`rate-limit off` cannot be combined with other rate-limit rules"));
        }
        return Ok(Vec::new());
    }
    let mut rules = nodes
        .iter()
        .map(parse_rate_limit)
        .collect::<Result<Vec<_>, _>>()?;
    if !rules.iter().any(|r| r.path.is_none()) {
        rules.insert(0, super::defaults::rate_limit());
    }
    Ok(rules)
}

fn parse_rate_limit(n: &NodeCtx<'_>) -> Result<RateLimitCfg, ConfigError> {
    n.check_args(0, 0)?;
    n.check_props(&["rps", "burst", "path"])?;
    let rps: u32 = n
        .prop_num("rps")?
        .ok_or_else(|| n.err("rate-limit requires `rps`"))?;
    let burst: u32 = n.prop_num("burst")?.unwrap_or(rps);
    if rps < 1 || burst < 1 {
        return Err(n.err("rate-limit rps and burst must be >= 1"));
    }
    let path = n.prop_str("path")?.map(str::to_string);
    if path.as_deref().is_some_and(|p| !p.starts_with('/')) {
        return Err(n.err("rate-limit path must start with `/`"));
    }
    Ok(RateLimitCfg { rps, burst, path })
}

pub fn parse_api_keys(n: &NodeCtx<'_>) -> Result<ApiKeysCfg, ConfigError> {
    n.check_args(0, 0)?;
    n.check_props(&["header"])?;
    let header = n.prop_str("header")?.unwrap_or("X-Api-Key").to_string();
    HeaderName::from_str(&header).map_err(|_| n.err("invalid api-keys header name"))?;
    let s = n.scope();
    s.check_only(&["key"])?;
    let mut keys: Vec<ApiKeyEntry> = Vec::new();
    for k in s.all("key") {
        k.check_args(1, 1)?;
        k.check_props(&["name"])?;
        let hex = k.arg_str(0)?.to_ascii_lowercase();
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(k.err("api key must be a 64 character sha256 hex digest"));
        }
        let name = k
            .prop_str("name")?
            .ok_or_else(|| k.err("api key requires `name`"))?
            .to_string();
        if keys.iter().any(|e| e.name == name) {
            return Err(k.err(format!("duplicate api key name `{name}`")));
        }
        keys.push(ApiKeyEntry { hash_hex: hex, name });
    }
    if keys.is_empty() {
        return Err(n.err("api-keys needs at least one key"));
    }
    Ok(ApiKeysCfg { header, keys })
}

/// `fallback off` disables the maintenance page (None).
pub fn parse_fallback(n: &NodeCtx<'_>) -> Result<Option<FallbackCfg>, ConfigError> {
    n.check_args(0, 1)?;
    if n.args().next().is_some() {
        if n.arg_str(0)? != "off" {
            return Err(n.err("fallback accepts only the argument `off`"));
        }
        n.check_props(&[])?;
        return Ok(None);
    }
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
    Ok(Some(FallbackCfg {
        status,
        show_incident_id: n.prop_bool("show-incident-id")?.unwrap_or(true),
        title: n.prop_str("title")?.map_or(d.title, str::to_string),
        message: n.prop_str("message")?.map_or(d.message, str::to_string),
        on,
    }))
}

/// `retry off` disables the retry on another backend. Returns whether retry is enabled.
pub fn parse_retry(n: &NodeCtx<'_>) -> Result<bool, ConfigError> {
    n.check_args(1, 1)?;
    n.check_props(&[])?;
    match n.arg_str(0)? {
        "off" => Ok(false),
        _ => Err(n.err("retry accepts only the argument `off`")),
    }
}
