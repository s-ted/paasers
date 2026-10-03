//! Authentication and transform configuration types.
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtKey {
    Hmac {
        secret: Vec<u8>,
    },
    PublicKeyPem {
        path: PathBuf,
        pem: Vec<u8>,
        kind: PemKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PemKind {
    Rsa,
    Ec,
    Ed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtCfg {
    pub key: JwtKey,
    pub algorithms: Vec<jsonwebtoken::Algorithm>,
    pub issuers: Vec<String>,
    pub audiences: Vec<String>,
    pub leeway: Duration,
    pub inject_headers: bool,
    pub cookie: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyEntry {
    pub hash_hex: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeysCfg {
    pub header: String,
    pub keys: Vec<ApiKeyEntry>,
}

#[derive(Debug, Clone)]
pub enum OpKind {
    Set(String),
    /// Built-in defaults only (no KDL syntax): keeps a value chosen by the backend.
    SetIfAbsent(String),
    Add(String),
    Remove,
    Replace(regex_lite::Regex, String),
}

impl PartialEq for OpKind {
    fn eq(&self, o: &Self) -> bool {
        match (self, o) {
            (Self::Set(a), Self::Set(b))
            | (Self::SetIfAbsent(a), Self::SetIfAbsent(b))
            | (Self::Add(a), Self::Add(b)) => a == b,
            (Self::Remove, Self::Remove) => true,
            (Self::Replace(r1, s1), Self::Replace(r2, s2)) => r1.as_str() == r2.as_str() && s1 == s2,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HeaderOpCfg {
    pub header: String,
    pub op: OpKind,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct TransformCfg {
    pub request: Vec<HeaderOpCfg>,
    pub response: Vec<HeaderOpCfg>,
    pub status: Vec<(u16, u16)>,
}
