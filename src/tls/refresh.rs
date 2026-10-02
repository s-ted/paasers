//! Applies the certificate selection of every TLS route to the resolver (idempotent, cheap).
use super::select::{AcmeCert, RENEW_BEFORE_SECS, Source, select};
use super::{CertManagerInner, HostCert, HostState, State, TlsRoute, pem, selfsigned};
use crate::config::TlsMode;
use crate::storage::now_unix;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

fn install(inner: &CertManagerInner, host: &str, st: &HostState) {
    match host.strip_prefix("*.") {
        Some(parent) => inner.resolver.set_wildcard(parent, st.key.clone()),
        None => inner.resolver.set(host, st.key.clone()),
    }
}

pub(super) async fn acme_cert(inner: &CertManagerInner, host: &str, directory: &str) -> Option<AcmeCert> {
    let r = inner.db.get_cert(host).await.ok().flatten()?;
    (r.directory == directory).then_some(())?;
    let key = pem::certified(&r.cert_pem, &r.key_pem).ok()?;
    Some(AcmeCert {
        key: Arc::new(key),
        not_after: r.not_after,
    })
}

fn rfc3339(unix: i64) -> String {
    humantime::format_rfc3339_seconds(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix.max(0).unsigned_abs()),
    )
    .to_string()
}

fn note_change(
    inner: &CertManagerInner,
    route: &TlsRoute,
    host: &str,
    prev: Option<&HostState>,
    new: &HostState,
) {
    let Some(prev) = prev else {
        tracing::info!(host, source = new.source.label(), "tls certificate selected");
        return;
    };
    if prev.source == new.source {
        return;
    }
    let (from, to) = (prev.source.label(), new.source.label());
    tracing::warn!(host, from, to, "tls certificate source changed");
    inner.incident(
        "tls_fallback",
        &route.id,
        &format!("host={host} {from} -> {to} not_after={}", rfc3339(new.not_after)),
    );
}

pub(super) async fn refresh(inner: &CertManagerInner, st: &mut State) {
    let now = now_unix();
    let mut hosts: HashMap<String, HostState> = HashMap::new();
    let routes = st.routes.clone();
    for route in &routes {
        match &route.mode {
            TlsMode::SelfSigned => {
                let cached = st
                    .selfsigned
                    .get(&route.id)
                    .filter(|e| e.0 == route.hosts && e.2 - now > RENEW_BEFORE_SECS)
                    .cloned();
                let entry = match cached {
                    Some(e) => e,
                    None => match selfsigned::generate(&route.hosts, now) {
                        Ok((k, na)) => (route.hosts.clone(), Arc::new(k), na),
                        Err(e) => {
                            tracing::error!(route = %route.id, error = %e, "cannot generate self-signed certificate");
                            continue;
                        }
                    },
                };
                st.selfsigned.insert(route.id.clone(), entry.clone());
                for h in &route.hosts {
                    let hs = HostState::new(Source::SelfSigned, entry.1.clone(), entry.2);
                    note_change(inner, route, h, st.hosts.get(h), &hs);
                    hosts.insert(h.clone(), hs);
                }
            }
            TlsMode::Auto { .. } => {
                let mut pending = Vec::new();
                for h in &route.hosts {
                    let acme = match &route.directory {
                        Some(d) => acme_cert(inner, h, d).await,
                        None => None,
                    };
                    match select(&st.index, h, now, acme.as_ref()) {
                        Some(s) => {
                            let mut hs = HostState::new(s.source, s.key, s.not_after);
                            hs.path = s.local.map(|l| l.source);
                            hs.directory = (s.source == Source::Acme)
                                .then(|| route.directory.clone())
                                .flatten();
                            note_change(inner, route, h, st.hosts.get(h), &hs);
                            hosts.insert(h.clone(), hs);
                        }
                        None => pending.push(h.clone()),
                    }
                }
                pending_hosts(inner, st, route, &pending, now, &mut hosts);
            }
        }
    }
    let active: HashSet<String> = hosts.keys().cloned().collect();
    st.temp.retain(|h, e| {
        active.contains(h)
            && hosts
                .get(h)
                .is_none_or(|x| x.source == Source::SelfSigned && e.1 > now)
    });
    for (h, hs) in &hosts {
        install(inner, h, hs);
    }
    inner.resolver.remove_not_in(&active);
    let default = st
        .gw
        .default_cert
        .as_ref()
        .and_then(|d| hosts.get(d))
        .map(|h| h.key.clone());
    inner.resolver.set_default(default);
    inner.report.store(Arc::new(
        hosts
            .iter()
            .map(|(h, s)| (h.clone(), HostCert::from(s)))
            .collect(),
    ));
    st.hosts = hosts;
}

/// Hosts with nothing usable: keep a previous local key if there was one, else a temporary self-signed.
fn pending_hosts(
    inner: &CertManagerInner,
    st: &mut State,
    route: &TlsRoute,
    pending: &[String],
    now: i64,
    out: &mut HashMap<String, HostState>,
) {
    let mut generate = Vec::new();
    for h in pending {
        match st.hosts.get(h) {
            // A vanished local file must not take a working certificate away.
            Some(p) if matches!(p.source, Source::Local | Source::LocalExpired) => {
                let mut kept = p.clone();
                kept.source = Source::LocalExpired;
                note_change(inner, route, h, st.hosts.get(h), &kept);
                out.insert(h.clone(), kept);
            }
            _ => match st.temp.get(h) {
                Some(t) if t.1 - now > RENEW_BEFORE_SECS => {
                    let hs = HostState::new(Source::SelfSigned, t.0.clone(), t.1);
                    out.insert(h.clone(), hs);
                }
                _ => generate.push(h.clone()),
            },
        }
    }
    if generate.is_empty() {
        return;
    }
    match selfsigned::generate(&generate, now) {
        Ok((k, na)) => {
            let k = Arc::new(k);
            for h in generate {
                st.temp.insert(h.clone(), (k.clone(), na));
                let hs = HostState::new(Source::SelfSigned, k.clone(), na);
                note_change(inner, route, &h, st.hosts.get(&h), &hs);
                out.insert(h, hs);
            }
        }
        Err(e) => tracing::error!(route = %route.id, error = %e, "cannot generate temporary certificate"),
    }
}
