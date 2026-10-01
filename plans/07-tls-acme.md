# P7: TLS & ACME (`src/tls/`)

## 1. Files

| File | Role |
|---|---|
| `tls/mod.rs` | `CertManager`, `TlsError`, `server_config()` |
| `tls/resolver.rs` | `CertResolver` (SNI => `CertifiedKey`) |
| `tls/selfsigned.rs` | temporary rcgen cert |
| `tls/pem.rs` | PEM => `CertifiedKey`, `not_after` |
| `tls/challenge.rs` | `ChallengeStore` (HTTP-01) |
| `tls/acme.rs` | ACME account + order (instant-acme) |
| `tls/worker.rs` | renewal loop, backoff |

## 2. `rustls::ServerConfig` (validated: SNI handshake OK in the spike)

```rust
pub fn server_config(resolver: Arc<CertResolver>) -> Result<rustls::ServerConfig, rustls::Error> {
    let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()?.with_no_client_auth().with_cert_resolver(resolver);
    c.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(c)
}
```
Built **once** at startup (the resolver is dynamic). Session tickets: rustls default (in-memory resumption).

## 3. Resolver (`resolver.rs`)

```rust
#[derive(Debug, Default)]
pub struct CertResolver {
    certs: ArcSwap<HashMap<String, Arc<rustls::sign::CertifiedKey>>>,  // exact domain -> key
    wildcard: ArcSwap<HashMap<String, Arc<CertifiedKey>>>,            // "client.com" -> key of "*.client.com" (file mode only)
    default: arc_swap::ArcSwapOption<CertifiedKey>,
}
impl rustls::server::ResolvesServerCert for CertResolver {
    fn resolve(&self, ch: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match ch.server_name() {
            Some(n) => { let n = n.to_ascii_lowercase();
                self.certs.load().get(&n).cloned()
                    .or_else(|| n.split_once('.').and_then(|(_, parent)| self.wildcard.load().get(parent).cloned())) }
            None => self.default.load_full(),
        }
    }
}
impl CertResolver {
    pub fn set(&self, domain: &str, key: Arc<CertifiedKey>) {         // copy-on-write (compiled)
        self.certs.rcu(|m| { let mut m = HashMap::clone(m); m.insert(domain.to_owned(), key.clone()); m });
    }
    pub fn set_wildcard(&self, parent: &str, key: Arc<CertifiedKey>);
    pub fn set_default(&self, key: Option<Arc<CertifiedKey>>) { self.default.store(key); }
    pub fn remove_not_in(&self, active: &HashSet<String>);           // on reload
}
```
Rare writes (issuance/reload): copy-on-write via `rcu` accepted. The resolver, `ChallengeStore` (§6) and `issue`/`account` (§7) were compiled as-is (strict clippy OK). `#[derive(Debug)]` is required by the `ResolvesServerCert` trait.

## 4. PEM => `CertifiedKey` (`pem.rs`, validated)

```rust
pub fn certified(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey, TlsError> {
    use rustls_pki_types::pem::PemObject;
    let certs = rustls_pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() { return Err(TlsError::Pem("no certificate".into())); }
    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;
    let sk = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)?;
    Ok(CertifiedKey::new(certs, sk))
}
pub fn not_after_unix(cert_pem: &str) -> Result<i64, TlsError> {
    let (_, p) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).map_err(|e| TlsError::Pem(e.to_string()))?;
    let x = p.parse_x509().map_err(|e| TlsError::Pem(e.to_string()))?;
    Ok(x.validity().not_after.timestamp())
}
```
`TlsError` (thiserror): `Pem(String)`, `Rustls(#[from] rustls::Error)`, `PemFile(#[from] rustls_pki_types::pem::Error)`, `Acme(#[from] instant_acme::Error)`, `Rcgen(#[from] rcgen::Error)`, `Json(#[from] serde_json::Error)`, `Storage(#[from] StorageError)`, `Io(#[from] std::io::Error)`, `Order(String)`.

## 5. Temporary certificate (`selfsigned.rs`, validated)

```rust
pub fn self_signed(hosts: &[String]) -> Result<CertifiedKey, TlsError> {
    let c = rcgen::generate_simple_self_signed(hosts.to_vec())?;
    certified(&c.cert.pem(), &c.signing_key.serialize_pem())
}
```
Never persisted. Served for each ACME host as long as no real certificate is in the database (avoids a handshake failure; the browser shows a warning, expected while issuance is in progress).

## 6. HTTP-01 (`challenge.rs`)

```rust
#[derive(Default)]
pub struct ChallengeStore { inner: std::sync::RwLock<HashMap<String, String>> }  // token -> key_authorization
impl ChallengeStore { pub fn put(&self, token: String, ka: String); pub fn get(&self, token: &str) -> Option<String>; pub fn remove(&self, token: &str); }
```
Poisoned lock => `unwrap_or_else(PoisonError::into_inner)`. Served by `EntryService` (plans/02 §5 step 6) on :80: `GET /.well-known/acme-challenge/{token}` => 200 `text/plain` body = key authorization; unknown token => 404. Token: `[A-Za-z0-9_-]+` otherwise 404.

## 7. ACME (`acme.rs`, instant-acme 0.8.5 API compiled)

### 7.1 Account
Storage key = directory URL. `directory_url(cfg)`: `Production` => `LetsEncrypt::Production.url()`, `Staging` => `LetsEncrypt::Staging.url()`, `Custom(u)` => `u`.
```rust
let builder = match &cfg.acme_ca_root { Some(p) => Account::builder_with_root(p)?, None => Account::builder()? };
let account = match db_get_account(dir).await? {
    Some(json) => builder.from_credentials(serde_json::from_str::<AccountCredentials>(&json)?).await?,
    None => {
        let contact = format!("mailto:{email}");
        let (acct, creds) = builder.create(&NewAccount { contact: &[&contact], terms_of_service_agreed: true,
                                                         only_return_existing: false }, dir.to_owned(), None).await?;
        db_put_account(dir, serde_json::to_string(&creds)?).await?;
        acct
    }
};
```
A single `Account` per directory, kept in the `CertManager` (reused). `builder_with_root` is used for pebble tests.

### 7.2 Order for a route (all its hosts as SAN)
```rust
let ids: Vec<Identifier> = hosts.iter().map(|h| Identifier::Dns(h.clone())).collect();
let mut order = account.new_order(&NewOrder::new(&ids)).await?;
let mut tokens = Vec::new();
{
    let mut auths = order.authorizations();
    while let Some(a) = auths.next().await {
        let mut a = a?;
        if a.status == AuthorizationStatus::Valid { continue; }
        let mut ch = a.challenge(ChallengeType::Http01).ok_or_else(|| TlsError::Order("no http-01 challenge".into()))?;
        challenges.put(ch.token.clone(), ch.key_authorization().as_str().to_owned());
        tokens.push(ch.token.clone());
        ch.set_ready().await?;
    }
}
let retry = RetryPolicy::new().initial_delay(Duration::from_secs(1)).backoff(2.0).timeout(Duration::from_secs(120));
let status = order.poll_ready(&retry).await;
tokens.iter().for_each(|t| challenges.remove(t));      // cleanup even on error
let status = status?;
if status != OrderStatus::Ready { return Err(TlsError::Order(format!("order status {status:?}"))); }
let key_pem = order.finalize().await?;                  // rcgen generates key + CSR (ECDSA P-256)
let chain_pem = order.poll_certificate(&retry).await?;
```
Then: `certified(&chain_pem, &key_pem)?` (validation), `not_after_unix`, write to the database under **each** host (plans/03 §5), `resolver.set(host, key)` for each host, `info!`.

The `{ ... }` block limits the mutable borrow of `order` by `authorizations()` (compiled this way in the spike).

## 8. `CertManager` and worker (`mod.rs`, `worker.rs`)

```rust
pub struct CertManager { db: Db, resolver: Arc<CertResolver>, challenges: Arc<ChallengeStore>,
                         recorder: Arc<FlightRecorder>, wanted: watch::Sender<Vec<TlsJob>> }
pub struct TlsJob { pub route_id: Arc<str>, pub hosts: Vec<String>, pub email: String }
```
### 8.1 `start(cfg, ...)` / `reconcile(cfg)`
For each route with `tls`:
* **File mode**: read the PEMs, `certified`, `resolver.set(host)` for each exact host, `set_wildcard(parent)` for `*.parent`. Error at startup => exit 2; on reload => route kept with the old cert + `error!`.
* **ACME mode**: for each host, load from the database; if present and `certified` OK => `resolver.set`; otherwise => `self_signed(hosts)` installed for the missing hosts. Add a `TlsJob`.
* `default-cert`: `set_default(resolver entry of the host)` after loading (if later issued by ACME, the worker also updates the default if `host == default_cert`).
* `resolver.remove_not_in(active_hosts)`.
* Publish the job list: `wanted.send_replace(jobs)`.

### 8.2 Worker (one task)
```text
loop {
  for each job in wanted.borrow().clone():
     if now < next_attempt[job.route_id]: continue
     not_after = min(not_after in database of the job's hosts) (absent => 0)
     if hosts in database != job hosts (host added) OR not_after - now < 30 days:
         match issue(job).await {
            Ok  => next_attempt[route] = 0 ; failures[route] = 0
            Err(e) => failures += 1 ; delay = min(60s * 2^(failures-1), 24h) ; next_attempt = now + delay
                      warn!(route, %e) ; recorder.record(Incident{kind:"acme", detail: e, route_id, ...})
         }
  select! { _ = sleep(jitter(12h +/- 1h)) , _ = wanted.changed() , _ = retry_tick(60s) , _ = shutdown.cancelled() => break }
}
```
* **Sequential** issuances (one order at a time: respects LE rate limits, KISS).
* `retry_tick(60s)`: wake-up to process due `next_attempt` entries.
* "hosts in database != job hosts": detected if at least one host of the job has no row in the database.
* The `Account` is created lazily on first need; creation failure => treated as a job failure (backoff).
* Jitter: `rand::random_range(0..7200)` seconds added to 11 h.

## 9. Tests

Unit:
- `pem::tests::certified_from_rcgen_pem`, `certified_rejects_garbage`, `not_after_matches_rcgen_params` (rcgen `not_after` set via `CertificateParams`).
- `resolver::tests::exact_then_wildcard_then_none`, `no_sni_uses_default`, `case_insensitive`.
- `challenge::tests::put_get_remove`.
- `worker::tests::backoff_schedule` (pure function `backoff(failures) -> Duration`: 1=>60 s, 2=>120 s, ... cap 24 h).
- `worker::tests::needs_renewal` (pure function: `(now, not_after, missing_hosts) -> bool`).

Integration:
- `tests/tls.rs::sni_serves_route_cert`: rcgen test CA + leaf (spike code: `CertificateParams::new(vec![..]).signed_by(&leaf_key, &Issuer::new(ca_params, &ca_key))`), route in `cert-file`/`key-file` mode (temporary files), rustls client with the CA as root => handshake + GET 200; h2 negotiated via ALPN.
- `tests/tls.rs::unknown_sni_rejected`.
- `tests/tls.rs::acme_route_serves_self_signed_before_issuance` (unreachable directory `https://127.0.0.1:1/dir` => handshake with self-signed cert containing the host in SAN; `acme` incident recorded).
- `tests/acme.rs` (`#[ignore]`, run in CI with pebble, see plans/12): real issuance via pebble, `acme-directory "https://localhost:14000/dir"`, `acme-ca-root "<pebble.minica.pem>"`, pebble configured with `httpPort` = gateway HTTP port; checks cert in database + served via SNI.

## 10. DoD P7
- [ ] Unit tests + `tests/tls.rs` green. Commit `P7: tls & acme`.
