//! In-memory self-signed certificates: the `self-signed` mode and the temporary certificate of auto mode.
use super::TlsError;
use super::pem::{certified, not_after_unix};
use rustls::sign::CertifiedKey;

/// Generates a certificate for `hosts` valid between one and two years from `now` (Unix seconds).
pub fn generate(hosts: &[String], now: i64) -> Result<(CertifiedKey, i64), TlsError> {
    let year = i32::try_from(1970 + (now + 365 * 86_400) / 31_556_952 + 1).unwrap_or(2100);
    let mut params = rcgen::CertificateParams::new(hosts.to_vec())?;
    params.not_after = rcgen::date_time_ymd(year, 1, 1);
    let key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    let pem = cert.pem();
    let not_after = not_after_unix(&pem)?;
    Ok((certified(&pem, &key.serialize_pem())?, not_after))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_contains_hosts_and_wildcards() {
        let now = crate::storage::now_unix();
        let hosts = ["a.example.com".to_string(), "*.b.example.com".to_string()];
        let (ck, na) = generate(&hosts, now).unwrap();
        let (_, x) = x509_parser::parse_x509_certificate(ck.cert[0].as_ref()).unwrap();
        let sans = format!(
            "{:?}",
            x.subject_alternative_name().unwrap().unwrap().value.general_names
        );
        assert!(sans.contains("a.example.com") && sans.contains("*.b.example.com"));
        assert!(na > now + 365 * 86_400);
        assert_eq!(x.issuer(), x.subject());
    }
}
