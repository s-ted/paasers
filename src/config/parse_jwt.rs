//! Parsing of the `jwt-validation` node.
use super::error::ConfigError;
use super::kdl_ext::{Env, NodeCtx};
use super::model_auth::*;
use super::units;
use jsonwebtoken::{Algorithm, DecodingKey};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

fn pem_kind(pem: &[u8]) -> Option<PemKind> {
    if DecodingKey::from_rsa_pem(pem).is_ok() {
        Some(PemKind::Rsa)
    } else if DecodingKey::from_ec_pem(pem).is_ok() {
        Some(PemKind::Ec)
    } else if DecodingKey::from_ed_pem(pem).is_ok() {
        Some(PemKind::Ed)
    } else {
        None
    }
}

fn alg_matches(key: &JwtKey, a: Algorithm) -> bool {
    use Algorithm::*;
    match key {
        JwtKey::Hmac { .. } => matches!(a, HS256 | HS384 | HS512),
        JwtKey::PublicKeyPem {
            kind: PemKind::Rsa, ..
        } => matches!(a, RS256 | RS384 | RS512 | PS256 | PS384 | PS512),
        JwtKey::PublicKeyPem {
            kind: PemKind::Ec, ..
        } => matches!(a, ES256 | ES384),
        JwtKey::PublicKeyPem {
            kind: PemKind::Ed, ..
        } => matches!(a, EdDSA),
    }
}

fn default_alg(key: &JwtKey) -> Algorithm {
    match key {
        JwtKey::Hmac { .. } => Algorithm::HS256,
        JwtKey::PublicKeyPem {
            kind: PemKind::Rsa, ..
        } => Algorithm::RS256,
        JwtKey::PublicKeyPem {
            kind: PemKind::Ec, ..
        } => Algorithm::ES256,
        JwtKey::PublicKeyPem {
            kind: PemKind::Ed, ..
        } => Algorithm::EdDSA,
    }
}

pub fn parse_jwt(n: &NodeCtx<'_>, env: Env<'_>) -> Result<JwtCfg, ConfigError> {
    n.check_args(0, 0)?;
    n.check_props(&[])?;
    let s = n.scope();
    s.check_only(&[
        "secret-env",
        "public-key-file",
        "algorithms",
        "issuer",
        "audience",
        "leeway",
        "inject-headers",
        "cookie",
    ])?;
    for name in [
        "secret-env",
        "public-key-file",
        "algorithms",
        "leeway",
        "inject-headers",
        "cookie",
    ] {
        s.single(name)?;
    }
    let key = match (s.single("secret-env")?, s.single("public-key-file")?) {
        (Some(_), Some(_)) | (None, None) => {
            return Err(n.err("jwt-validation needs exactly one of secret-env / public-key-file"));
        }
        (Some(e), None) => {
            let var = e.one_str()?;
            match env(var).filter(|v| !v.is_empty()) {
                Some(v) => JwtKey::Hmac {
                    secret: v.into_bytes(),
                },
                None => return Err(e.err(format!("environment variable `{var}` is missing or empty"))),
            }
        }
        (None, Some(f)) => {
            let path = PathBuf::from(f.one_str()?);
            let pem =
                std::fs::read(&path).map_err(|e| f.err(format!("cannot read {}: {e}", path.display())))?;
            let kind = pem_kind(&pem).ok_or_else(|| f.err("unsupported or invalid public key PEM"))?;
            JwtKey::PublicKeyPem { path, pem, kind }
        }
    };
    let algorithms = match s.single("algorithms")? {
        Some(a) => {
            a.check_props(&[])?;
            let v: Vec<Algorithm> = a
                .args_str()?
                .into_iter()
                .map(|x| Algorithm::from_str(x).map_err(|_| a.err(format!("unknown algorithm `{x}`"))))
                .collect::<Result<_, _>>()?;
            if v.is_empty() || v.iter().any(|x| !alg_matches(&key, *x)) {
                return Err(a.err("algorithms missing or incompatible with the key"));
            }
            v
        }
        None => vec![default_alg(&key)],
    };
    let strings = |name: &str| -> Result<Vec<String>, ConfigError> {
        Ok(s.all(name)
            .iter()
            .map(|c| c.args_str())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .map(str::to_string)
            .collect())
    };
    Ok(JwtCfg {
        key,
        algorithms,
        issuers: strings("issuer")?,
        audiences: strings("audience")?,
        leeway: match s.single("leeway")? {
            Some(l) => units::parse_duration(l.one_str()?).map_err(|m| l.err(m))?,
            None => Duration::from_secs(60),
        },
        inject_headers: match s.single("inject-headers")? {
            Some(i) => {
                i.check_args(1, 1)?;
                i.arg_bool(0)?
            }
            None => true,
        },
        cookie: s
            .single("cookie")?
            .map(|c| c.one_str().map(str::to_string))
            .transpose()?,
    })
}
