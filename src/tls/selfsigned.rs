//! Temporary self-signed certificate, served while the first ACME issuance is pending.
use super::TlsError;
use super::pem::certified;
use rustls::sign::CertifiedKey;

pub fn self_signed(hosts: &[String]) -> Result<CertifiedKey, TlsError> {
    let c = rcgen::generate_simple_self_signed(hosts.to_vec())?;
    certified(&c.cert.pem(), &c.signing_key.serialize_pem())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_contains_hosts() {
        let ck = self_signed(&["a.example.com".into(), "b.example.com".into()]).unwrap();
        let (_, x) = x509_parser::parse_x509_certificate(ck.cert[0].as_ref()).unwrap();
        let sans = format!(
            "{:?}",
            x.subject_alternative_name().unwrap().unwrap().value.general_names
        );
        assert!(sans.contains("a.example.com") && sans.contains("b.example.com"));
    }
}
