//! SNI certificate resolver with lock-free reads and copy-on-write updates.
use arc_swap::{ArcSwap, ArcSwapOption};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

type KeyMap = HashMap<String, Arc<CertifiedKey>>;

#[derive(Debug, Default)]
pub struct CertResolver {
    certs: ArcSwap<KeyMap>,
    /// `"client.com"` maps to the key of `*.client.com` (file mode only).
    wildcard: ArcSwap<KeyMap>,
    default: ArcSwapOption<CertifiedKey>,
}

impl CertResolver {
    pub fn set(&self, domain: &str, key: Arc<CertifiedKey>) {
        self.certs.rcu(|m| {
            let mut m = KeyMap::clone(m);
            m.insert(domain.to_ascii_lowercase(), key.clone());
            m
        });
    }

    pub fn set_wildcard(&self, parent: &str, key: Arc<CertifiedKey>) {
        self.wildcard.rcu(|m| {
            let mut m = KeyMap::clone(m);
            m.insert(parent.to_ascii_lowercase(), key.clone());
            m
        });
    }

    pub fn set_default(&self, key: Option<Arc<CertifiedKey>>) {
        self.default.store(key);
    }

    pub fn get(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        self.certs.load().get(&domain.to_ascii_lowercase()).cloned()
    }

    /// Drops entries of hosts that are no longer configured.
    pub fn remove_not_in(&self, active: &HashSet<String>) {
        self.certs.rcu(|m| {
            m.iter()
                .filter(|(k, _)| active.contains(*k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<KeyMap>()
        });
        let parents: HashSet<String> = active
            .iter()
            .filter_map(|h| h.strip_prefix("*.").map(str::to_string))
            .collect();
        self.wildcard.rcu(|m| {
            m.iter()
                .filter(|(k, _)| parents.contains(*k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<KeyMap>()
        });
    }

    pub fn resolve_name(&self, name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        match name {
            Some(n) => {
                let n = n.to_ascii_lowercase();
                self.certs.load().get(&n).cloned().or_else(|| {
                    n.split_once('.')
                        .and_then(|(_, parent)| self.wildcard.load().get(parent).cloned())
                })
            }
            None => self.default.load_full(),
        }
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, ch: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolve_name(ch.server_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::selfsigned::self_signed;

    fn key(host: &str) -> Arc<CertifiedKey> {
        Arc::new(self_signed(&[host.to_string()]).unwrap())
    }

    #[test]
    fn exact_then_wildcard_then_none() {
        let r = CertResolver::default();
        let (exact, wild) = (key("a.example.com"), key("*.example.com"));
        r.set("a.example.com", exact.clone());
        r.set_wildcard("example.com", wild.clone());
        assert!(Arc::ptr_eq(
            &r.resolve_name(Some("a.example.com")).unwrap(),
            &exact
        ));
        assert!(Arc::ptr_eq(
            &r.resolve_name(Some("b.example.com")).unwrap(),
            &wild
        ));
        assert!(r.resolve_name(Some("x.y.example.com")).is_none());
        assert!(r.resolve_name(Some("other.org")).is_none());
    }

    #[test]
    fn no_sni_uses_default() {
        let r = CertResolver::default();
        assert!(r.resolve_name(None).is_none());
        let d = key("d.example.com");
        r.set_default(Some(d.clone()));
        assert!(Arc::ptr_eq(&r.resolve_name(None).unwrap(), &d));
        r.set_default(None);
        assert!(r.resolve_name(None).is_none());
    }

    #[test]
    fn case_insensitive() {
        let r = CertResolver::default();
        r.set("A.Example.com", key("a.example.com"));
        assert!(r.resolve_name(Some("a.EXAMPLE.com")).is_some());
    }

    #[test]
    fn remove_not_in_prunes() {
        let r = CertResolver::default();
        r.set("a.com", key("a.com"));
        r.set("b.com", key("b.com"));
        r.set_wildcard("c.com", key("*.c.com"));
        r.remove_not_in(&HashSet::from(["a.com".to_string()]));
        assert!(r.get("a.com").is_some() && r.get("b.com").is_none());
        assert!(r.resolve_name(Some("x.c.com")).is_none());
    }
}
