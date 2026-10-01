//! Integration tests for TLS termination and certificate handling (P7).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod common;
use common::*;
use rcgen::{CertificateParams, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, ServerName};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

struct TestPki {
    ca_der: CertificateDer<'static>,
    cert_path: PathBuf,
    key_path: PathBuf,
    _dir: tempfile::TempDir,
}

fn pki(hosts: &[&str]) -> TestPki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "paasers test ca");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_params =
        CertificateParams::new(hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>()).unwrap();
    let leaf = leaf_params
        .signed_by(&leaf_key, &Issuer::new(ca_params, &ca_key))
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
    std::fs::write(&cert_path, leaf.pem()).unwrap();
    std::fs::write(&key_path, leaf_key.serialize_pem()).unwrap();
    TestPki {
        ca_der: ca_cert.der().clone(),
        cert_path,
        key_path,
        _dir: dir,
    }
}

fn connector(root: &CertificateDer<'static>, alpn: &[&[u8]]) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let mut c =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    TlsConnector::from(Arc::new(c))
}

fn https_addr(g: &GatewayHandle) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], g.addrs.https.unwrap().port()))
}

fn kdl(upstream: SocketAddr, pki: &TestPki, storage: &std::path::Path) -> String {
    format!(
        "gateway {{\n listen \"127.0.0.1:0\" \"127.0.0.1:0\"\n storage-path \"{}\"\n}}\nroute \"secure.test\" {{\n tls cert-file=\"{}\" key-file=\"{}\"\n upstream \"{upstream}\"\n}}\n",
        storage.display(),
        pki.cert_path.display(),
        pki.key_path.display()
    )
}

#[tokio::test]
async fn sni_serves_route_cert_and_h2_reaches_h1_backend() {
    let (backend, _h) = spawn_echo_backend().await;
    let p = pki(&["secure.test"]);
    let dir = tempfile::tempdir().unwrap();
    let g = spawn_gateway(&kdl(backend, &p, &dir.path().join("c.db"))).await;
    let tcp = TcpStream::connect(https_addr(&g)).await.unwrap();
    let tls = connector(&p.ca_der, &[b"h2", b"http/1.1"])
        .connect(ServerName::try_from("secure.test").unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tls),
    )
    .await
    .unwrap();
    tokio::spawn(conn);
    let req = http::Request::builder()
        .uri("https://secure.test/hello")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let h = resp.headers();
    // The backend only speaks HTTP/1.1 and must have received a Host header plus our headers.
    assert_eq!(h["x-seen-host"], "secure.test");
    assert_eq!(h["x-seen-x-forwarded-proto"], "https");
    assert_eq!(h["x-seen-x-forwarded-for"], "127.0.0.1");
    g.stop().await;
}

#[tokio::test]
async fn http1_over_tls_works_and_http_is_redirected() {
    let (backend, _h) = spawn_echo_backend().await;
    let p = pki(&["secure.test"]);
    let dir = tempfile::tempdir().unwrap();
    let g = spawn_gateway(&kdl(backend, &p, &dir.path().join("c.db"))).await;
    let tcp = TcpStream::connect(https_addr(&g)).await.unwrap();
    let mut tls = connector(&p.ca_der, &[b"http/1.1"])
        .connect(ServerName::try_from("secure.test").unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(b"GET / HTTP/1.1\r\nHost: secure.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out).await;
    assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200"));
    let r = raw_request(
        g.http_addr(),
        "GET /p HTTP/1.1\r\nHost: secure.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        r.starts_with("HTTP/1.1 301") && r.contains("https://secure.test:"),
        "{r}"
    );
    g.stop().await;
}

#[tokio::test]
async fn unknown_sni_rejected() {
    let (backend, _h) = spawn_echo_backend().await;
    let p = pki(&["secure.test"]);
    let dir = tempfile::tempdir().unwrap();
    let g = spawn_gateway(&kdl(backend, &p, &dir.path().join("c.db"))).await;
    let tcp = TcpStream::connect(https_addr(&g)).await.unwrap();
    let r = connector(&p.ca_der, &[b"http/1.1"])
        .connect(ServerName::try_from("nope.test").unwrap(), tcp)
        .await;
    assert!(r.is_err());
    g.stop().await;
}

#[tokio::test]
async fn acme_route_serves_self_signed_before_issuance() {
    let (backend, _h) = spawn_echo_backend().await;
    let dir = tempfile::tempdir().unwrap();
    let src = format!(
        "gateway {{\n listen \"127.0.0.1:0\" \"127.0.0.1:0\"\n storage-path \"{}\"\n acme-directory \"https://127.0.0.1:1/dir\"\n}}\nroute \"acme.test\" \"www.acme.test\" {{\n tls email=\"a@b.c\"\n upstream \"{backend}\"\n}}\n",
        dir.path().join("c.db").display()
    );
    let g = spawn_gateway(&src).await;
    // A verifier that accepts anything: we only inspect the presented certificate.
    #[derive(Debug)]
    struct Any;
    impl rustls::client::danger::ServerCertVerifier for Any {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
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
    let cfg =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Any))
            .with_no_client_auth();
    let tcp = TcpStream::connect(https_addr(&g)).await.unwrap();
    let tls = TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from("www.acme.test").unwrap(), tcp)
        .await
        .unwrap();
    let der = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
    let (_, x) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
    let sans = format!(
        "{:?}",
        x.subject_alternative_name().unwrap().unwrap().value.general_names
    );
    assert!(
        sans.contains("acme.test") && sans.contains("www.acme.test"),
        "{sans}"
    );
    // The unreachable directory makes the worker record an acme incident.
    let mut seen = false;
    for _ in 0..60 {
        if g.shared
            .recorder
            .query(&Default::default())
            .iter()
            .any(|i| i.kind == "acme")
        {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(seen, "no acme incident recorded");
    g.stop().await;
}

#[tokio::test]
async fn acme_challenge_is_served_on_http_listener() {
    let (backend, _h) = spawn_echo_backend().await;
    let dir = tempfile::tempdir().unwrap();
    let src = format!(
        "gateway {{\n listen \"127.0.0.1:0\" \"127.0.0.1:0\"\n storage-path \"{}\"\n acme-directory \"https://127.0.0.1:1/dir\"\n}}\nroute \"acme.test\" {{\n tls email=\"a@b.c\"\n upstream \"{backend}\"\n}}\n",
        dir.path().join("c.db").display()
    );
    let g = spawn_gateway(&src).await;
    g.shared.challenges.put("tok-1".into(), "tok-1.thumbprint".into());
    let ask = |t: &str| {
        format!(
            "GET /.well-known/acme-challenge/{t} HTTP/1.1\r\nHost: acme.test\r\nConnection: close\r\n\r\n"
        )
    };
    let r = raw_request(g.http_addr(), &ask("tok-1")).await;
    assert!(
        r.starts_with("HTTP/1.1 200") && r.ends_with("tok-1.thumbprint"),
        "{r}"
    );
    let r = raw_request(g.http_addr(), &ask("unknown")).await;
    assert!(r.starts_with("HTTP/1.1 404"), "{r}");
    g.stop().await;
}
