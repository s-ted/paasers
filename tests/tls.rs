//! Integration tests for TLS termination and certificate handling (P7).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod common;
use common::*;
use rcgen::{CertificateParams, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, ServerName};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

struct TestPki {
    ca_der: CertificateDer<'static>,
    leaf_der: CertificateDer<'static>,
    certs_dir: tempfile::TempDir,
    ca: (CertificateParams, KeyPair, CertificateDer<'static>),
}

struct Leaf {
    cert_pem: String,
    key_pem: String,
    der: CertificateDer<'static>,
}

trait CloneParts {
    fn clone_parts(&self) -> (CertificateParams, KeyPair, CertificateDer<'static>);
}
impl CloneParts for (CertificateParams, KeyPair, CertificateDer<'static>) {
    fn clone_parts(&self) -> (CertificateParams, KeyPair, CertificateDer<'static>) {
        (
            self.0.clone(),
            KeyPair::try_from(self.1.serialize_der().as_slice()).unwrap(),
            self.2.clone(),
        )
    }
}

fn ca() -> (CertificateParams, KeyPair, CertificateDer<'static>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "paasers test ca");
    let der = ca_params.clone().self_signed(&ca_key).unwrap().der().clone();
    (ca_params, ca_key, der)
}

fn leaf(
    ca: &(CertificateParams, KeyPair, CertificateDer<'static>),
    hosts: &[&str],
    years: (i32, i32),
) -> Leaf {
    let (ca_params, ca_key, _) = ca.clone_parts();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>()).unwrap();
    params.not_before = rcgen::date_time_ymd(years.0, 1, 1);
    params.not_after = rcgen::date_time_ymd(years.1, 1, 1);
    let cert = params.signed_by(&key, &Issuer::new(ca_params, &ca_key)).unwrap();
    Leaf {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        der: cert.der().clone(),
    }
}

fn write_leaf(dir: &std::path::Path, l: &Leaf) {
    std::fs::write(dir.join("fullchain.pem"), &l.cert_pem).unwrap();
    std::fs::write(dir.join("privkey.pem"), &l.key_pem).unwrap();
}

fn pki(hosts: &[&str]) -> TestPki {
    let ca = ca();
    let l = leaf(&ca, hosts, (2020, 2040));
    let dir = tempfile::tempdir().unwrap();
    write_leaf(dir.path(), &l);
    TestPki {
        ca_der: ca.2.clone(),
        leaf_der: l.der,
        certs_dir: dir,
        ca,
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
        "gateway {{\n listen \"127.0.0.1:0\" \"127.0.0.1:0\"\n storage-path \"{}\"\n certs-dir \"{}\"\n}}\nroute \"secure.test\" {{\n tls\n upstream \"{upstream}\"\n}}\n",
        storage.display(),
        pki.certs_dir.path().display(),
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

/// Verifier accepting anything: lets tests inspect which certificate is presented.
#[derive(Debug)]
struct AnyCert;
impl rustls::client::danger::ServerCertVerifier for AnyCert {
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

/// Handshakes with `sni` and returns the presented leaf certificate (DER).
async fn presented(g: &GatewayHandle, sni: &str) -> CertificateDer<'static> {
    let cfg =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert))
            .with_no_client_auth();
    let tcp = TcpStream::connect(https_addr(g)).await.unwrap();
    let tls = TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from(sni.to_string()).unwrap(), tcp)
        .await
        .unwrap();
    tls.get_ref().1.peer_certificates().unwrap()[0]
        .clone()
        .into_owned()
}

fn gw(storage: &std::path::Path, certs: &std::path::Path, routes: &str) -> String {
    format!(
        "gateway {{\n listen \"127.0.0.1:0\" \"127.0.0.1:0\"\n storage-path \"{}\"\n certs-dir \"{}\"\n acme-directory \"https://127.0.0.1:1/dir\"\n default-email \"a@b.c\"\n}}\n{routes}",
        storage.display(),
        certs.display()
    )
}

fn has_incident(g: &GatewayHandle, kind: &str) -> bool {
    g.shared
        .recorder
        .query(&Default::default())
        .iter()
        .any(|i| i.kind == kind)
}

async fn wait_for(mut f: impl AsyncFnMut() -> bool) -> bool {
    for _ in 0..80 {
        if f().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn wildcard_local_cert_served() {
    let (backend, _h) = spawn_echo_backend().await;
    let p = pki(&["*.wild.test"]);
    let dir = tempfile::tempdir().unwrap();
    let src = gw(
        &dir.path().join("c.db"),
        p.certs_dir.path(),
        &format!("route \"*.wild.test\" {{\n tls\n upstream \"{backend}\"\n}}\n"),
    );
    let g = spawn_gateway(&src).await;
    let tcp = TcpStream::connect(https_addr(&g)).await.unwrap();
    let r = connector(&p.ca_der, &[b"http/1.1"])
        .connect(ServerName::try_from("x.wild.test").unwrap(), tcp)
        .await;
    assert!(r.is_ok(), "{:?}", r.err());
    g.stop().await;
}

#[tokio::test]
async fn certs_dir_change_is_picked_up() {
    let (backend, _h) = spawn_echo_backend().await;
    let p = pki(&["secure.test"]);
    let dir = tempfile::tempdir().unwrap();
    let g = spawn_gateway(&kdl(backend, &p, &dir.path().join("c.db"))).await;
    assert_eq!(presented(&g, "secure.test").await, p.leaf_der);
    let renewed = leaf(&p.ca, &["secure.test"], (2021, 2041));
    write_leaf(p.certs_dir.path(), &renewed);
    let want = renewed.der.clone();
    let mut seen = false;
    for _ in 0..80 {
        if presented(&g, "secure.test").await == want {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(seen, "renewed certificate was not picked up");
    g.stop().await;
}

fn acme_record(l: &Leaf, domain: &str, directory: &str) -> paasers::storage::certs::CertRecord {
    paasers::storage::certs::CertRecord {
        domain: domain.into(),
        cert_pem: l.cert_pem.clone(),
        key_pem: l.key_pem.clone(),
        not_after: 2_208_988_800,
        issued_at: 1,
        directory: directory.into(),
    }
}

#[tokio::test]
async fn expired_local_switches_to_acme_cert() {
    let (backend, _h) = spawn_echo_backend().await;
    let ca = ca();
    let expired = leaf(&ca, &["secure.test"], (2020, 2021));
    let acme = leaf(&ca, &["secure.test"], (2020, 2040));
    let dir = tempfile::tempdir().unwrap();
    let certs = tempfile::tempdir().unwrap();
    write_leaf(certs.path(), &expired);
    let db_path = dir.path().join("c.db");
    {
        let db = paasers::storage::Db::open(&db_path).await.unwrap();
        db.put_cert(acme_record(&acme, "secure.test", "https://127.0.0.1:1/dir"))
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    let src = gw(
        &db_path,
        certs.path(),
        &format!("route \"secure.test\" {{\n tls\n upstream \"{backend}\"\n}}\n"),
    );
    let g = spawn_gateway(&src).await;
    assert_eq!(presented(&g, "secure.test").await, acme.der);
    g.stop().await;
}

#[tokio::test]
async fn acme_cert_from_other_directory_is_ignored() {
    let (backend, _h) = spawn_echo_backend().await;
    let ca = ca();
    let expired = leaf(&ca, &["secure.test"], (2020, 2021));
    let stale = leaf(&ca, &["secure.test"], (2020, 2040));
    let dir = tempfile::tempdir().unwrap();
    let certs = tempfile::tempdir().unwrap();
    write_leaf(certs.path(), &expired);
    let db_path = dir.path().join("c.db");
    {
        let db = paasers::storage::Db::open(&db_path).await.unwrap();
        db.put_cert(acme_record(&stale, "secure.test", "https://other-ca/dir"))
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    let src = gw(
        &db_path,
        certs.path(),
        &format!("route \"secure.test\" {{\n tls\n upstream \"{backend}\"\n}}\n"),
    );
    let g = spawn_gateway(&src).await;
    // Wrong directory: the expired local certificate is the last resort, not the stored ACME one.
    assert_eq!(presented(&g, "secure.test").await, expired.der);
    g.stop().await;
}

#[tokio::test]
async fn expired_local_kept_when_acme_fails() {
    let (backend, _h) = spawn_echo_backend().await;
    let ca = ca();
    let expired = leaf(&ca, &["secure.test"], (2020, 2021));
    let dir = tempfile::tempdir().unwrap();
    let certs = tempfile::tempdir().unwrap();
    write_leaf(certs.path(), &expired);
    let src = gw(
        &dir.path().join("c.db"),
        certs.path(),
        &format!("route \"secure.test\" {{\n tls\n upstream \"{backend}\"\n}}\n"),
    );
    let g = spawn_gateway(&src).await;
    assert_eq!(presented(&g, "secure.test").await, expired.der);
    // The unreachable directory makes issuance fail and be recorded, the expired certificate stays.
    assert!(
        wait_for(async || has_incident(&g, "acme")).await,
        "no acme incident"
    );
    assert_eq!(presented(&g, "secure.test").await, expired.der);
    g.stop().await;
}

#[tokio::test]
async fn self_signed_route_serves_generated_cert() {
    let (backend, _h) = spawn_echo_backend().await;
    let dir = tempfile::tempdir().unwrap();
    let src = format!(
        "gateway {{\n listen \"127.0.0.1:0\" \"127.0.0.1:0\"\n storage-path \"{}\"\n}}\nroute \"lan.test\" \"*.lan.test\" {{\n tls self-signed=#true\n upstream \"{backend}\"\n}}\n",
        dir.path().join("c.db").display()
    );
    let g = spawn_gateway(&src).await;
    for sni in ["lan.test", "x.lan.test"] {
        let der = presented(&g, sni).await;
        let (_, x) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
        assert_eq!(x.issuer(), x.subject());
        let sans = format!(
            "{:?}",
            x.subject_alternative_name().unwrap().unwrap().value.general_names
        );
        assert!(sans.contains("lan.test") && sans.contains("*.lan.test"), "{sans}");
    }
    assert!(!has_incident(&g, "acme"));
    g.stop().await;
}

#[tokio::test]
async fn local_cert_replaces_temporary_and_records_fallback() {
    // Starts with nothing (temporary self-signed), then a local certificate appears: source switches, incident recorded.
    let (backend, _h) = spawn_echo_backend().await;
    let ca = ca();
    let certs = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let probe = leaf(&ca, &["other.test"], (2020, 2040));
    write_leaf(certs.path(), &probe);
    let src = gw(
        &dir.path().join("c.db"),
        certs.path(),
        &format!("route \"secure.test\" {{\n tls\n upstream \"{backend}\"\n}}\n"),
    );
    let g = spawn_gateway(&src).await;
    let temp = presented(&g, "secure.test").await;
    assert_ne!(temp, probe.der);
    let real = leaf(&ca, &["secure.test"], (2020, 2040));
    write_leaf(certs.path(), &real);
    let want = real.der.clone();
    let mut ok = false;
    for _ in 0..80 {
        if presented(&g, "secure.test").await == want {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ok);
    assert!(has_incident(&g, "tls_fallback"));
    g.stop().await;
}
