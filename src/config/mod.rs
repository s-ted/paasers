//! KDL configuration: parsing into a validated `Config`.
pub mod error;
pub mod kdl_ext;
pub mod model;
pub mod model_auth;
mod parse;
mod parse_features;
pub(crate) mod parse_gate;
mod parse_jwt;
mod parse_route;
mod parse_transform;
pub mod units;
mod validate;

pub use error::ConfigError;
pub use model::*;
pub use model_auth::*;

use kdl_ext::{Env, Scope, parse_doc};
use std::path::Path;

/// Parses and validates a configuration. `env` resolves `*-env` references.
pub fn parse_str(src: &str, env: Env<'_>) -> Result<Config, ConfigError> {
    let doc = parse_doc(src)?;
    let scope = Scope {
        nodes: doc.nodes(),
        src,
    };
    scope.check_only(&["gateway", "mcp-server", "route"])?;
    let gateway = match scope.single("gateway")? {
        Some(g) => parse::parse_gateway(&g)?,
        None => parse::default_gateway(),
    };
    let mcp = scope
        .single("mcp-server")?
        .map(|m| parse::parse_mcp(&m, env))
        .transpose()?;
    let routes = scope
        .all("route")
        .iter()
        .map(|r| parse_route::parse_route(r, &gateway, env))
        .collect::<Result<Vec<_>, _>>()?;
    let cfg = Config { gateway, mcp, routes };
    validate::validate(&cfg)?;
    Ok(cfg)
}

/// Reads, parses and validates a configuration file using the process environment.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let src = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_str(&src, &|k| std::env::var(k).ok())
}

#[cfg(test)]
mod tests;
