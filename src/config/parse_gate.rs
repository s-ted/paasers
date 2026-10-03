//! Parsing of the `gatekeeper` node.
use super::error::ConfigError;
use super::kdl_ext::{Env, NodeCtx};
use super::model::GatekeeperCfg;
use super::units;
use std::time::Duration;

const MIN_TOTP_BYTES: usize = 16;

/// Validates an argon2id PHC string.
pub fn check_psk_hash(s: &str) -> Result<(), String> {
    let parsed =
        argon2::password_hash::phc::PasswordHash::new(s).map_err(|e| format!("invalid psk hash: {e}"))?;
    if parsed.algorithm.as_str() != "argon2id" {
        return Err("psk must be an argon2id hash".into());
    }
    Ok(())
}

fn totp_secret(b32: &str) -> Result<Vec<u8>, String> {
    let s = totp_rs::Secret::try_from_base32(b32.trim())
        .map_err(|_| "totp secret is not valid base32".to_string())?;
    let bytes = s.as_bytes().to_vec();
    if bytes.len() < MIN_TOTP_BYTES {
        return Err(format!("totp secret must be at least {MIN_TOTP_BYTES} bytes"));
    }
    Ok(bytes)
}

fn from_env(n: &NodeCtx<'_>, env: Env<'_>) -> Result<String, ConfigError> {
    let var = n.one_str()?;
    env(var)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| n.err(format!("environment variable `{var}` is missing or empty")))
}

pub fn parse_gatekeeper(n: &NodeCtx<'_>, tls: bool, env: Env<'_>) -> Result<GatekeeperCfg, ConfigError> {
    n.check_args(0, 0)?;
    n.check_props(&[])?;
    let s = n.scope();
    s.check_only(&[
        "title",
        "psk",
        "psk-env",
        "totp-secret",
        "totp-secret-env",
        "session-duration",
        "rate-limit",
        "cookie-name",
    ])?;
    for name in [
        "title",
        "psk",
        "psk-env",
        "totp-secret",
        "totp-secret-env",
        "session-duration",
        "rate-limit",
        "cookie-name",
    ] {
        s.single(name)?;
    }
    let psk_hash = match (s.single("psk")?, s.single("psk-env")?) {
        (Some(p), None) => (p.one_str()?.to_string(), p),
        (None, Some(p)) => (from_env(&p, env)?, p),
        _ => return Err(n.err("gatekeeper needs exactly one of psk / psk-env")),
    };
    check_psk_hash(&psk_hash.0).map_err(|m| psk_hash.1.err(m))?;
    let totp = match (s.single("totp-secret")?, s.single("totp-secret-env")?) {
        (Some(_), Some(e)) => return Err(e.err("totp-secret and totp-secret-env are mutually exclusive")),
        (Some(t), None) => Some((t.one_str()?.to_string(), t)),
        (None, Some(t)) => Some((from_env(&t, env)?, t)),
        (None, None) => None,
    };
    let totp_secret = totp
        .map(|(v, node)| totp_secret(&v).map_err(|m| node.err(m)))
        .transpose()?;
    let session_duration = match s.single("session-duration")? {
        Some(d) => {
            let v = units::parse_duration(d.one_str()?).map_err(|m| d.err(m))?;
            if v < Duration::from_secs(60) || v > Duration::from_secs(90 * 86400) {
                return Err(d.err("session-duration must be between 1m and 90d"));
            }
            v
        }
        None => Duration::from_secs(14 * 86400),
    };
    let (mut attempts, mut window) = (5u32, Duration::from_secs(900));
    if let Some(r) = s.single("rate-limit")? {
        r.check_args(0, 0)?;
        r.check_props(&["attempts", "window"])?;
        attempts = r.prop_num("attempts")?.unwrap_or(attempts);
        window = r.prop_dur("window")?.unwrap_or(window);
        if attempts < 1 {
            return Err(r.err("attempts must be >= 1"));
        }
    }
    let cookie_name = match s.single("cookie-name")? {
        Some(c) => {
            let v = c.one_str()?;
            if v.is_empty()
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err(c.err("cookie-name must match [A-Za-z0-9_-]+"));
            }
            v.to_string()
        }
        None => (if tls { "__Host-gate" } else { "__gate" }).to_string(),
    };
    Ok(GatekeeperCfg {
        title: s
            .single("title")?
            .map(|t| t.one_str().map(str::to_string))
            .transpose()?
            .unwrap_or_else(|| "Protected access".into()),
        psk_hash: psk_hash.0,
        totp_secret,
        session_duration,
        attempts,
        window,
        cookie_name,
    })
}
