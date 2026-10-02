//! Local certificate directory: PEM discovery, key/certificate pairing by public key and lookup by host.
use rustls::sign::{CertifiedKey, SigningKey};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use x509_parser::extensions::GeneralName;

#[derive(Debug, Clone)]
pub struct LocalCert {
    pub key: Arc<CertifiedKey>,
    pub names: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
    pub source: PathBuf,
}

#[derive(Debug, Default, Clone)]
pub struct LocalIndex {
    certs: Vec<LocalCert>,
}

struct Leaf {
    spki: Vec<u8>,
    names: Vec<String>,
    not_before: i64,
    not_after: i64,
}

fn parse_leaf(der: &CertificateDer<'_>) -> Option<Leaf> {
    let (_, x) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
    let mut names: Vec<String> = x
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|e| {
            e.value
                .general_names
                .iter()
                .filter_map(|g| match g {
                    GeneralName::DNSName(d) => Some(d.to_ascii_lowercase()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    // The common name is only a fallback for certificates without a SAN extension.
    if names.is_empty() && x.subject_alternative_name().ok().flatten().is_none() {
        names.extend(
            x.subject()
                .iter_common_name()
                .filter_map(|c| c.as_str().ok())
                .map(str::to_ascii_lowercase),
        );
    }
    Some(Leaf {
        spki: x.tbs_certificate.subject_pki.raw.to_vec(),
        names,
        not_before: x.validity().not_before.timestamp(),
        not_after: x.validity().not_after.timestamp(),
    })
}

/// `*.a.com` covers `x.a.com` only. A wildcard host is covered only by the same wildcard name.
pub fn covers(names: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    names.iter().any(|n| {
        *n == host
            || (!host.starts_with("*.")
                && n.strip_prefix("*.").is_some_and(|p| {
                    host.split_once('.')
                        .is_some_and(|(label, rest)| !label.is_empty() && rest == p)
                }))
    })
}

impl LocalIndex {
    /// Never fails: unreadable or unusable files are skipped with a warning.
    pub fn load(dir: &Path) -> LocalIndex {
        let mut files = Vec::new();
        match std::fs::read_dir(dir) {
            Ok(rd) => {
                let mut paths: Vec<PathBuf> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
                paths.sort();
                for p in paths {
                    let hidden = p
                        .file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with('.'));
                    if hidden || !std::fs::metadata(&p).is_ok_and(|m| m.is_file()) {
                        continue;
                    }
                    match std::fs::read(&p) {
                        Ok(b) => files.push((p, b)),
                        Err(e) => {
                            tracing::warn!(file = %p.display(), error = %e, "cannot read certificate file")
                        }
                    }
                }
            }
            Err(e) => tracing::warn!(dir = %dir.display(), error = %e, "cannot read certs-dir"),
        }
        Self::from_pems(&files)
    }

    pub fn from_pems(files: &[(PathBuf, Vec<u8>)]) -> LocalIndex {
        let mut chains: Vec<(PathBuf, Vec<CertificateDer<'static>>)> = Vec::new();
        let mut keys: Vec<(Vec<u8>, PrivateKeyDer<'static>, PathBuf)> = Vec::new();
        for (path, bytes) in files {
            let chain: Vec<_> = CertificateDer::pem_slice_iter(bytes)
                .map_while(Result::ok)
                .collect();
            if !chain.is_empty() {
                chains.push((path.clone(), chain));
            }
            for k in PrivateKeyDer::pem_slice_iter(bytes).map_while(Result::ok) {
                let sk: Option<Arc<dyn SigningKey>> =
                    rustls::crypto::aws_lc_rs::sign::any_supported_type(&k).ok();
                match sk.and_then(|s| s.public_key().map(|p| p.as_ref().to_vec())) {
                    Some(spki) => keys.push((spki, k, path.clone())),
                    None => tracing::warn!(file = %path.display(), "unsupported private key ignored"),
                }
            }
        }
        let mut used = vec![false; keys.len()];
        let mut certs = Vec::new();
        for (path, chain) in chains {
            let Some(leaf) = chain.first().and_then(parse_leaf) else {
                tracing::warn!(file = %path.display(), "unparsable certificate ignored");
                continue;
            };
            let Some(i) = keys.iter().position(|(spki, _, _)| *spki == leaf.spki) else {
                tracing::warn!(file = %path.display(), "certificate without private key ignored");
                continue;
            };
            if let Some(u) = used.get_mut(i) {
                *u = true;
            }
            let sk = keys
                .get(i)
                .and_then(|(_, k, _)| rustls::crypto::aws_lc_rs::sign::any_supported_type(k).ok());
            if let Some(sk) = sk {
                certs.push(LocalCert {
                    key: Arc::new(CertifiedKey::new(chain, sk)),
                    names: leaf.names,
                    not_before: leaf.not_before,
                    not_after: leaf.not_after,
                    source: path,
                });
            }
        }
        for ((_, _, path), u) in keys.iter().zip(used) {
            if !u {
                tracing::warn!(file = %path.display(), "private key without certificate ignored");
            }
        }
        LocalIndex { certs }
    }

    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    /// Best certificate covering `host` and valid at `now`; the one expiring last wins.
    pub fn best_valid(&self, host: &str, now: i64) -> Option<&LocalCert> {
        self.certs
            .iter()
            .filter(|c| c.not_before <= now && now <= c.not_after && covers(&c.names, host))
            .max_by_key(|c| c.not_after)
    }

    /// Same, ignoring validity (last resort).
    pub fn best_any(&self, host: &str) -> Option<&LocalCert> {
        self.certs
            .iter()
            .filter(|c| covers(&c.names, host))
            .max_by_key(|c| c.not_after)
    }
}

/// Cheap change detector of a directory: sorted `(name, mtime, len)`.
pub fn dir_stamp(dir: &Path) -> Vec<(String, Option<std::time::SystemTime>, u64)> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|e| {
            let m = std::fs::metadata(e.path()).ok()?;
            Some((
                e.file_name().to_string_lossy().into_owned(),
                m.modified().ok(),
                m.len(),
            ))
        })
        .collect();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) struct Made {
        pub cert: String,
        pub key: String,
    }

    /// `(not_before, not_after)` as years; `san = false` produces a CN-only certificate.
    pub(crate) fn make(names: &[&str], years: (i32, i32), san: bool) -> Made {
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        if san {
            p.subject_alt_names = names
                .iter()
                .map(|n| rcgen::SanType::DnsName((*n).try_into().unwrap()))
                .collect();
        } else {
            p.distinguished_name.push(rcgen::DnType::CommonName, names[0]);
        }
        p.not_before = rcgen::date_time_ymd(years.0, 1, 1);
        p.not_after = rcgen::date_time_ymd(years.1, 1, 1);
        let k = rcgen::KeyPair::generate().unwrap();
        Made {
            cert: p.self_signed(&k).unwrap().pem(),
            key: k.serialize_pem(),
        }
    }

    fn f(n: &str, c: &str) -> (PathBuf, Vec<u8>) {
        (PathBuf::from(n), c.as_bytes().to_vec())
    }

    const NOW: i64 = 1_800_000_000; // 2027-01-15
    const OK: (i32, i32) = (2020, 2040);

    #[test]
    fn pairs_key_and_cert_across_files() {
        let m = make(&["a.com"], OK, true);
        let idx = LocalIndex::from_pems(&[f("privkey.pem", &m.key), f("fullchain.pem", &m.cert)]);
        let c = idx.best_valid("a.com", NOW).unwrap();
        assert_eq!(c.source, PathBuf::from("fullchain.pem"));
    }

    #[test]
    fn pairs_cert_and_key_in_one_file() {
        let m = make(&["a.com"], OK, true);
        let idx = LocalIndex::from_pems(&[f("both.pem", &format!("{}{}", m.cert, m.key))]);
        assert!(idx.best_valid("a.com", NOW).is_some());
    }

    #[test]
    fn ignores_orphans_and_garbage() {
        let a = make(&["a.com"], OK, true);
        let b = make(&["b.com"], OK, true);
        let idx = LocalIndex::from_pems(&[
            f("a.crt", &a.cert),
            f("b.key", &b.key),
            f("junk.txt", "hello"),
            f(
                "bad.pem",
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
            ),
        ]);
        assert!(idx.is_empty());
    }

    #[test]
    fn best_valid_exact_and_wildcard() {
        let w = make(&["*.a.com"], OK, true);
        let idx = LocalIndex::from_pems(&[f("w.pem", &format!("{}{}", w.cert, w.key))]);
        assert!(idx.best_valid("x.a.com", NOW).is_some());
        assert!(idx.best_valid("a.com", NOW).is_none());
        assert!(idx.best_valid("x.y.a.com", NOW).is_none());
        assert!(idx.best_valid("*.a.com", NOW).is_some());
        let e = make(&["a.com"], OK, true);
        let idx = LocalIndex::from_pems(&[f("e.pem", &format!("{}{}", e.cert, e.key))]);
        assert!(idx.best_valid("*.a.com", NOW).is_none());
    }

    #[test]
    fn best_valid_prefers_latest_expiry() {
        let a = make(&["a.com"], (2020, 2030), true);
        let b = make(&["a.com"], (2020, 2035), true);
        let idx = LocalIndex::from_pems(&[
            f("a.pem", &format!("{}{}", a.cert, a.key)),
            f("b.pem", &format!("{}{}", b.cert, b.key)),
        ]);
        assert_eq!(
            idx.best_valid("a.com", NOW).unwrap().source,
            PathBuf::from("b.pem")
        );
    }

    #[test]
    fn expired_excluded_from_valid_but_kept_for_any() {
        let m = make(&["a.com"], (2020, 2025), true);
        let idx = LocalIndex::from_pems(&[f("a.pem", &format!("{}{}", m.cert, m.key))]);
        assert!(idx.best_valid("a.com", NOW).is_none());
        assert!(idx.best_any("a.com").is_some());
    }

    #[test]
    fn not_yet_valid_excluded() {
        let m = make(&["a.com"], (2035, 2040), true);
        let idx = LocalIndex::from_pems(&[f("a.pem", &format!("{}{}", m.cert, m.key))]);
        assert!(idx.best_valid("a.com", NOW).is_none());
    }

    #[test]
    fn cn_used_only_without_san() {
        let m = make(&["cn.a.com"], OK, false);
        let idx = LocalIndex::from_pems(&[f("a.pem", &format!("{}{}", m.cert, m.key))]);
        assert!(idx.best_valid("cn.a.com", NOW).is_some());
        // rcgen always writes a SAN when names are given, so a CN is ignored in that case.
        let m = make(&["san.a.com"], OK, true);
        let idx = LocalIndex::from_pems(&[f("a.pem", &format!("{}{}", m.cert, m.key))]);
        assert!(idx.best_valid("rcgen-default-cn", NOW).is_none());
    }

    #[test]
    fn load_reads_directory_skipping_hidden_and_subdirs() {
        let d = tempfile::tempdir().unwrap();
        let m = make(&["a.com"], OK, true);
        std::fs::write(d.path().join("c.pem"), format!("{}{}", m.cert, m.key)).unwrap();
        std::fs::write(d.path().join(".hidden.pem"), "x").unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        let idx = LocalIndex::load(d.path());
        assert!(idx.best_any("a.com").is_some());
        let s1 = dir_stamp(d.path());
        std::fs::write(d.path().join("new.txt"), "n").unwrap();
        assert_ne!(s1, dir_stamp(d.path()));
        assert!(LocalIndex::load(&d.path().join("missing")).is_empty());
    }
}
