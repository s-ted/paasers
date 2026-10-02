//! The `tls` node of a route.
use super::error::ConfigError;
use super::kdl_ext::NodeCtx;
use super::model::*;

pub(super) fn parse_tls(n: &NodeCtx<'_>, gw: &GatewayCfg, hosts: &[String]) -> Result<TlsCfg, ConfigError> {
    n.check_args(0, 0)?;
    if n.prop("cert-file").is_some() || n.prop("key-file").is_some() {
        return Err(n.err("tls: `cert-file`/`key-file` were removed, use gateway `certs-dir`"));
    }
    n.check_props(&["email", "self-signed"])?;
    let scope = n.scope();
    scope.check_only(&["staging"])?;
    let staging = match scope.single("staging")? {
        Some(s) => {
            s.check_args(0, 0)?;
            s.check_props(&[])?;
            s.scope().check_only(&[])?;
            true
        }
        None => false,
    };
    if n.prop_bool("self-signed")?.unwrap_or(false) {
        if n.prop("email").is_some() {
            return Err(n.err("tls: self-signed does not use ACME, remove `email`"));
        }
        if staging {
            return Err(n.err("tls: `staging` only applies to ACME"));
        }
        return Ok(TlsCfg {
            mode: TlsMode::SelfSigned,
        });
    }
    let email = n
        .prop_str("email")?
        .map(str::to_string)
        .or_else(|| gw.default_email.clone());
    let wildcard = hosts.iter().any(|h| h.starts_with("*."));
    let acme = email
        .filter(|_| !wildcard)
        .map(|email| AcmeTarget { email, staging });
    Ok(TlsCfg {
        mode: TlsMode::Auto { acme },
    })
}
