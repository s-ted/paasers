//! PEM to rustls `CertifiedKey` conversion and certificate expiry.
use super::TlsError;
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

pub fn certified(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey, TlsError> {
    let certs = CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(TlsError::Pem("no certificate".into()));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;
    let sk = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)?;
    Ok(CertifiedKey::new(certs, sk))
}

/// Expiry (Unix seconds) of the first certificate of the chain.
pub fn not_after_unix(cert_pem: &str) -> Result<i64, TlsError> {
    let (_, p) =
        x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).map_err(|e| TlsError::Pem(e.to_string()))?;
    let x = p.parse_x509().map_err(|e| TlsError::Pem(e.to_string()))?;
    Ok(x.validity().not_after.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_cert(not_after_year: i32) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec!["a.example.com".to_string()]).unwrap();
        params.not_after = rcgen::date_time_ymd(not_after_year, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn certified_from_rcgen_pem() {
        let (c, k) = gen_cert(2040);
        let ck = certified(&c, &k).unwrap();
        assert_eq!(ck.cert.len(), 1);
    }

    #[test]
    fn certified_rejects_garbage() {
        assert!(certified("nope", "nope").is_err());
        let (c, _) = gen_cert(2040);
        assert!(certified(&c, "nope").is_err());
        let (_, k) = gen_cert(2040);
        assert!(certified("", &k).is_err());
    }

    #[test]
    fn not_after_matches_rcgen_params() {
        let (c, _) = gen_cert(2040);
        // 2040-01-01T00:00:00Z
        assert_eq!(not_after_unix(&c).unwrap(), 2_208_988_800);
        assert!(not_after_unix("garbage").is_err());
    }
}
