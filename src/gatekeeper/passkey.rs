//! WebAuthn passkeys: registration after a PSK login, and passkey-only login afterwards.
use super::login::{safe_next, session_cookie};
use super::{GateError, GateRt};
use crate::prelude::{IncidentKind, Resp, simple};
use http::StatusCode;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    Url, Uuid,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

const PENDING_TTL: Duration = Duration::from_secs(300);
const PENDING_MAX: usize = 1000;
pub const MAX_JSON_BYTES: usize = 64 * 1024;

pub enum Ceremony {
    Register(PasskeyRegistration, Arc<str>),
    Login(PasskeyAuthentication, Arc<str>),
}

/// In-memory ceremony state (the webauthn-rs state types are not serializable without the danger feature).
#[derive(Default)]
pub struct Pending {
    inner: Mutex<HashMap<String, (Instant, Ceremony)>>,
}

impl Pending {
    /// `None` when the table is full (caller answers 429).
    pub fn put(&self, c: Ceremony) -> Option<String> {
        let mut m = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        m.retain(|_, (t, _)| t.elapsed() < PENDING_TTL);
        if m.len() >= PENDING_MAX {
            return None;
        }
        let id = hex::encode(rand::random::<[u8; 16]>());
        m.insert(id.clone(), (Instant::now(), c));
        Some(id)
    }

    /// Single use: the state is removed when taken.
    pub fn take(&self, id: &str) -> Option<Ceremony> {
        let (t, c) = self
            .inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id)?;
        (t.elapsed() < PENDING_TTL).then_some(c)
    }
}

/// One `Webauthn` per host: rp_id = host, origin = `https://host[:port]`.
pub fn build_webauthn(
    hosts: &[String],
    title: &str,
    https_port: Option<u16>,
) -> Result<HashMap<String, Arc<Webauthn>>, GateError> {
    let mut out = HashMap::new();
    for h in hosts.iter().filter(|h| !h.starts_with("*.")) {
        let origin = match https_port {
            Some(p) if p != 443 && p != 0 => format!("https://{h}:{p}"),
            _ => format!("https://{h}"),
        };
        let url = Url::parse(&origin).map_err(|e| GateError::Build(e.to_string()))?;
        let wa = WebauthnBuilder::new(h, &url)
            .map_err(|e| GateError::Build(e.to_string()))?
            .rp_name(title)
            .build()
            .map_err(|e| GateError::Build(e.to_string()))?;
        out.insert(h.clone(), Arc::new(wa));
    }
    Ok(out)
}

fn json(status: StatusCode, v: &serde_json::Value) -> Resp {
    simple(status, "application/json", v.to_string())
}

fn failed() -> Resp {
    let mut r = json(
        StatusCode::BAD_REQUEST,
        &serde_json::json!({"ok": false, "error": "passkey_failed"}),
    );
    r.extensions_mut().insert(IncidentKind("auth"));
    r
}

fn unavailable() -> Resp {
    json(
        StatusCode::TOO_MANY_REQUESTS,
        &serde_json::json!({"ok": false, "error": "try_later"}),
    )
}

fn ok_json(extra: serde_json::Value) -> Resp {
    let mut v = serde_json::json!({"ok": true});
    if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
        o.extend(e.clone());
    }
    json(StatusCode::OK, &v)
}

async fn stored(rt: &GateRt) -> Vec<(Vec<u8>, Passkey)> {
    let Some(db) = &rt.shared.db else {
        return Vec::new();
    };
    db.list_passkeys(&rt.route_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| {
            serde_json::from_str::<Passkey>(&r.passkey_json)
                .ok()
                .map(|p| (r.cred_id, p))
        })
        .collect()
}

pub async fn has_any(rt: &GateRt) -> bool {
    !stored(rt).await.is_empty()
}

pub async fn register_start(rt: &GateRt, host: &str) -> Resp {
    let Some(wa) = rt.webauthn.get(host) else {
        return failed();
    };
    let exclude = stored(rt)
        .await
        .iter()
        .map(|(_, p)| p.cred_id().clone())
        .collect::<Vec<_>>();
    let Ok((ccr, state)) = wa.start_passkey_registration(Uuid::new_v4(), "team", "Team", Some(exclude))
    else {
        return failed();
    };
    match rt
        .shared
        .pending
        .put(Ceremony::Register(state, rt.route_id.clone()))
    {
        Some(id) => json(StatusCode::OK, &serde_json::json!({"id": id, "options": ccr})),
        None => unavailable(),
    }
}

#[derive(serde::Deserialize)]
struct RegisterFinish {
    id: String,
    credential: RegisterPublicKeyCredential,
    #[serde(default)]
    label: String,
}

pub async fn register_finish(rt: &GateRt, host: &str, body: &[u8]) -> Resp {
    let (Some(wa), Ok(req)) = (
        rt.webauthn.get(host),
        serde_json::from_slice::<RegisterFinish>(body),
    ) else {
        return failed();
    };
    let Some(Ceremony::Register(state, route)) = rt.shared.pending.take(&req.id) else {
        return failed();
    };
    if route != rt.route_id {
        return failed();
    }
    let Ok(pk) = wa.finish_passkey_registration(&req.credential, &state) else {
        return failed();
    };
    let (Some(db), Ok(json_pk)) = (&rt.shared.db, serde_json::to_string(&pk)) else {
        return failed();
    };
    let label: String = req.label.chars().take(64).collect();
    match db
        .add_passkey(&rt.route_id, pk.cred_id().as_ref(), &json_pk, &label)
        .await
    {
        Ok(()) => ok_json(serde_json::json!({})),
        Err(_) => failed(),
    }
}

pub async fn login_start(rt: &GateRt, host: &str, ip: std::net::IpAddr) -> Resp {
    if let Err(secs) = rt.limiter.check(ip) {
        let mut r = unavailable();
        if let Ok(v) = http::HeaderValue::from_str(&secs.to_string()) {
            r.headers_mut().insert(http::header::RETRY_AFTER, v);
        }
        return r;
    }
    let Some(wa) = rt.webauthn.get(host) else {
        return failed();
    };
    let keys: Vec<Passkey> = stored(rt).await.into_iter().map(|(_, p)| p).collect();
    if keys.is_empty() {
        return json(
            StatusCode::NOT_FOUND,
            &serde_json::json!({"ok": false, "error": "no_passkey"}),
        );
    }
    let Ok((rcr, state)) = wa.start_passkey_authentication(&keys) else {
        return failed();
    };
    match rt.shared.pending.put(Ceremony::Login(state, rt.route_id.clone())) {
        Some(id) => json(StatusCode::OK, &serde_json::json!({"id": id, "options": rcr})),
        None => unavailable(),
    }
}

#[derive(serde::Deserialize)]
struct LoginFinish {
    id: String,
    credential: PublicKeyCredential,
    #[serde(default)]
    next: String,
}

pub async fn login_finish(rt: &GateRt, host: &str, body: &[u8]) -> Resp {
    let (Some(wa), Ok(req)) = (rt.webauthn.get(host), serde_json::from_slice::<LoginFinish>(body)) else {
        return failed();
    };
    let Some(Ceremony::Login(state, route)) = rt.shared.pending.take(&req.id) else {
        return failed();
    };
    if route != rt.route_id {
        return failed();
    }
    let Ok(res) = wa.finish_passkey_authentication(&req.credential, &state) else {
        return failed();
    };
    if let Some(db) = &rt.shared.db {
        for (cred_id, mut pk) in stored(rt).await {
            if pk.cred_id() == res.cred_id() {
                if pk.update_credential(&res) == Some(true)
                    && let Ok(j) = serde_json::to_string(&pk)
                {
                    let _ = db.update_passkey(&cred_id, &j).await;
                }
                break;
            }
        }
    }
    let mut r = ok_json(serde_json::json!({"next": safe_next(&req.next)}));
    if let Ok(v) = http::HeaderValue::from_str(&session_cookie(rt, 'k')) {
        r.headers_mut().append(http::header::SET_COOKIE, v);
    }
    r
}
