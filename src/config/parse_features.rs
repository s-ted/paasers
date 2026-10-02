//! Parsing of cache, compression, geoip, rate-limit, jwt, api-keys and transform nodes.
use super::error::ConfigError;
use super::kdl_ext::NodeCtx;
use super::model::*;
use super::model_auth::*;
use super::units;
use http::HeaderName;
use std::path::PathBuf;
use std::str::FromStr;

pub fn parse_cache(n: &NodeCtx<'_>) -> Result<CacheCfg, ConfigError> {
    n.check_args(0, 0)?;
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
    Ok(CacheCfg {
        max_size,
        stale_while_revalidate: n.prop_dur("stale-while-revalidate")?.unwrap_or_default(),
        stale_if_error: n.prop_dur("stale-if-error")?.unwrap_or_default(),
        default_ttl: n.prop_dur("default-ttl")?.unwrap_or_default(),
        max_object_size,
    })
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

pub fn parse_rate_limit(n: &NodeCtx<'_>) -> Result<RateLimitCfg, ConfigError> {
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
