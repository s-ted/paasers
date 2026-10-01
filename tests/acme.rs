//! Real ACME issuance against pebble (CI only). Run with `PEBBLE_DIR=target/pebble cargo test --test acme -- --ignored`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod common;
use common::*;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DOMAIN: &str = "acme-test.localhost";
const HTTP_PORT: u16 = 5002;
const HTTPS_PORT: u16 = 5443;

/// Accepts any certificate and keeps the chain it saw: only used to inspect what the gateway serves.
#[derive(Debug)]
struct Capture(Mutex<Vec<Vec<u8>>>);

impl rustls::client::danger::ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.0.lock().unwrap().push(end.to_vec());
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn served_cert(addr: std::net::SocketAddr) -> Option<Vec<u8>> {
    let cap = Arc::new(Capture(Mutex::new(Vec::new())));
    let cfg =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(cap.clone())
            .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(addr).await.ok()?;
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from(DOMAIN.to_string()).ok()?, tcp)
        .await
        .ok()?;
    cap.0.lock().unwrap().first().cloned()
}

#[tokio::test]
#[ignore = "needs pebble: scripts/pebble.sh, then PEBBLE_DIR=target/pebble cargo test --test acme -- --ignored"]
async fn issues_a_certificate_through_pebble() {
    let Ok(pebble_dir) = std::env::var("PEBBLE_DIR") else {
        println!("skipped: PEBBLE_DIR is not set");
        return;
    };
    if tokio::net::lookup_host((DOMAIN, 80)).await.is_err() {
        println!("skipped: {DOMAIN} does not resolve on this machine");
        return;
    }
    let (backend, _j) = spawn_echo_backend().await;
    let dir = tempfile::tempdir().unwrap();
    let src = format!(
        "gateway {{\n listen \"[::]:{HTTP_PORT}\" \"[::]:{HTTPS_PORT}\"\n storage-path \"{}\"\n acme-directory \"https://127.0.0.1:14000/dir\"\n acme-ca-root \"{pebble_dir}/pebble.minica.pem\"\n default-email \"t@example.com\"\n}}\nroute \"{DOMAIN}\" {{\n tls\n upstream \"{backend}\"\n}}\n",
        dir.path().join("db").display()
    );
    let cfg = paasers::config::parse_str(&src, &|_| None).unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let token = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(paasers::server::run_with(cfg, None, tx, token.clone()));
    rx.await.unwrap();
    let v6 = std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], HTTPS_PORT));
    let mut issued = false;
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(der) = served_cert(v6).await {
            let (_, x) = x509_parser::parse_x509_certificate(&der).unwrap();
            if x.issuer() != x.subject() {
                issued = true;
                break;
            }
        }
    }
    assert!(issued, "no CA-issued certificate within 60 s");
    token.cancel();
    let _ = task.await;
    let db = paasers::storage::Db::open(&dir.path().join("db")).await.unwrap();
    assert!(
        db.get_cert(DOMAIN).await.unwrap().is_some(),
        "certificate must be persisted"
    );
}
