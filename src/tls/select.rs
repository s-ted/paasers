//! Pure certificate selection and issuance decisions (auto mode).
use super::local::{LocalCert, LocalIndex};
use rustls::sign::CertifiedKey;
use std::sync::Arc;

pub const RENEW_BEFORE_SECS: i64 = 30 * 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Local,
    Acme,
    LocalExpired,
    SelfSigned,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Local => "local",
            Source::Acme => "acme",
            Source::LocalExpired => "local-expired",
            Source::SelfSigned => "self-signed",
        }
    }
}

/// A valid ACME certificate read from the database for the route's directory.
pub struct AcmeCert {
    pub key: Arc<CertifiedKey>,
    pub not_after: i64,
}

pub struct Selected {
    pub source: Source,
    pub key: Arc<CertifiedKey>,
    pub not_after: i64,
    pub local: Option<LocalCert>,
}

fn local(c: &LocalCert, source: Source) -> Selected {
    Selected {
        source,
        key: c.key.clone(),
        not_after: c.not_after,
        local: Some(c.clone()),
    }
}

/// Local valid > ACME valid > expired local (only when no ACME). `None` means a temporary self-signed is needed.
pub fn select(idx: &LocalIndex, host: &str, now: i64, acme: Option<&AcmeCert>) -> Option<Selected> {
    if let Some(c) = idx.best_valid(host, now) {
        return Some(local(c, Source::Local));
    }
    if let Some(a) = acme.filter(|a| a.not_after > now) {
        return Some(Selected {
            source: Source::Acme,
            key: a.key.clone(),
            not_after: a.not_after,
            local: None,
        });
    }
    idx.best_any(host).map(|c| local(c, Source::LocalExpired))
}

/// Issue when neither a local nor an ACME certificate will still be valid in 30 days.
pub fn needs_issue(now: i64, local_until: Option<i64>, acme_until: Option<i64>) -> bool {
    let soon = |u: Option<i64>| u.is_none_or(|u| u - now < RENEW_BEFORE_SECS);
    soon(local_until) && soon(acme_until)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::selfsigned::generate;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn index(years: (i32, i32)) -> LocalIndex {
        let mut p = rcgen::CertificateParams::new(vec!["a.com".to_string()]).unwrap();
        p.not_before = rcgen::date_time_ymd(years.0, 1, 1);
        p.not_after = rcgen::date_time_ymd(years.1, 1, 1);
        let k = rcgen::KeyPair::generate().unwrap();
        let pem = format!("{}{}", p.self_signed(&k).unwrap().pem(), k.serialize_pem());
        LocalIndex::from_pems(&[("a.pem".into(), pem.into_bytes())])
    }

    fn acme(not_after: i64) -> AcmeCert {
        AcmeCert {
            key: Arc::new(generate(&["a.com".into()], NOW).unwrap().0),
            not_after,
        }
    }

    #[test]
    fn select_local_first() {
        let s = select(&index((2020, 2040)), "a.com", NOW, Some(&acme(NOW + 80 * DAY))).unwrap();
        assert_eq!(s.source, Source::Local);
    }

    #[test]
    fn select_acme_when_local_expired() {
        let s = select(&index((2020, 2025)), "a.com", NOW, Some(&acme(NOW + 80 * DAY))).unwrap();
        assert_eq!(s.source, Source::Acme);
    }

    #[test]
    fn select_expired_local_when_no_acme() {
        let s = select(&index((2020, 2025)), "a.com", NOW, None).unwrap();
        assert_eq!(s.source, Source::LocalExpired);
        let s = select(&index((2020, 2025)), "a.com", NOW, Some(&acme(NOW - DAY))).unwrap();
        assert_eq!(s.source, Source::LocalExpired);
    }

    #[test]
    fn select_none_means_self_signed() {
        assert!(select(&LocalIndex::default(), "a.com", NOW, None).is_none());
        assert_eq!(Source::SelfSigned.label(), "self-signed");
    }

    #[test]
    fn needs_issue_matrix() {
        assert!(needs_issue(NOW, None, None));
        assert!(!needs_issue(NOW, Some(NOW + 60 * DAY), None));
        assert!(needs_issue(NOW, Some(NOW + 10 * DAY), None));
        assert!(!needs_issue(NOW, Some(NOW + 10 * DAY), Some(NOW + 80 * DAY)));
        assert!(!needs_issue(NOW, Some(NOW - DAY), Some(NOW + 80 * DAY)));
        assert!(needs_issue(NOW, Some(NOW + 10 * DAY), Some(NOW + 10 * DAY)));
    }
}
