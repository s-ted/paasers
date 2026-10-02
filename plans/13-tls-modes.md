# P13: TLS modes (local certificate directory, self-signed, ACME staging per route)

> Status: **implemented** (commit `P13: tls modes`). Implemented after P12 under the usual rule: `cargo check`, `cargo test`
> and `cargo clippy --all-targets -- -D warnings` (with and without `passkey`) green before the commit `P13: tls modes`.
> This plan **supersedes** the TLS parts of `plans/01` §3.8 and `plans/07` §8.1 where they conflict (sub-plan > PLAN.md).

## 1. Goals and decisions

| # | Decision |
|---|---|
| T1 | TLS stays optional per route: no `tls` node ⇒ the route is plain HTTP on the HTTP listener only (unchanged). |
| T2 | Two TLS modes only: **auto** (`tls`) and **self-signed** (`tls self-signed=#true`). |
| T3 | **auto** = local certificate from `gateway.certs-dir` when one is valid for the host, otherwise Let's Encrypt (ACME HTTP-01), otherwise a temporary self-signed certificate. Fully transparent, per host. |
| T4 | `cert-file` / `key-file` are **removed**. A directory with two files replaces them. |
| T5 | ACME staging is chosen **per route** with an optional child node `staging` of `tls`. It overrides `gateway.acme-directory`, which stays the global default. |
| T6 | Continuity of service: ACME issuance starts **proactively** when a local certificate enters the 30-day renewal window (or is missing), while the local certificate keeps being served until it expires. |
| T7 | Last resort when the local certificate has expired **and** ACME has failed: keep serving the **expired local certificate** (clearer browser error than an unknown issuer) and record an incident. |
| T8 | `redirect-https` defaults to `#true` for every TLS route, whatever the mode. |
| T9 | Every switch of the certificate source for a host is logged (`warn!`) and recorded (`kind="tls_fallback"`); MCP reports the source per host. |

## 2. Grammar (replaces `plans/01` §3.8)

```text
gateway {
    certs-dir "<directory>"            // optional, default none (no local certificates)
    acme-directory "production"|"staging"|"<https url>"   // unchanged: global default
}

route <host>+ {
    tls [email="<email>"] [self-signed=#true] {   // children optional
        staging                                    // optional, no argument, no property
    }
}
```

Rules (config errors unless stated):
* `self-signed=#true` together with `email` ⇒ error `self-signed does not use ACME`.
* `self-signed=#true` together with `staging` ⇒ error `staging only applies to ACME`.
* `staging` is a singleton child with no argument and no property. Any other child of `tls` ⇒ `unknown node`.
* `cert-file` / `key-file` ⇒ `unknown property` (removed, T4). The error message adds a hint: `use gateway certs-dir`.
* `self-signed=#false` is equivalent to omitting the property.
* `certs-dir` must be a readable directory when set (validated at load).

```rust
pub enum TlsMode { Auto { acme: Option<AcmeTarget> }, SelfSigned }
/// `None` when ACME is impossible for this route (see §5): only local certificates can be used.
pub struct AcmeTarget { pub email: String, pub staging: bool }
pub struct TlsCfg { pub mode: TlsMode }               // replaces the old enum TlsCfg { Acme, Files }
// GatewayCfg gains: pub certs_dir: Option<PathBuf>
```

Examples:

```kdl
gateway { certs-dir "/etc/paasers/certs"; default-email "ops@example.com"; }

route "client.com" "www.client.com" { tls; upstream "10.0.1.10:8080" }          // local if present, else LE
route "dev.client.com" { tls { staging }; upstream "10.0.1.11:8080" }           // LE staging
route "*.preview.client.com" { tls; upstream "10.0.1.12:8080" }                 // needs a local wildcard cert
route "intranet.lan" { tls self-signed=#true; upstream "10.0.1.13:8080" }       // generated
route "plain.client.com" { upstream "10.0.1.14:8080" }                          // HTTP only
```

## 3. Local certificate directory (`tls/local.rs`)

### 3.1 Loading (pure function over the directory listing + file contents)

1. List the regular files of `certs-dir` (not recursive, symlinks followed, hidden files ignored). File names do not matter.
2. Parse every PEM block of every file (`rustls_pki_types::pem::PemObject`): collect certificate chains (consecutive
   `CERTIFICATE` blocks of one file, leaf first) and private keys (PKCS#8, PKCS#1, SEC1).
3. **Pairing** by public key: a key matches a chain when the SubjectPublicKeyInfo of the key (derived via
   `rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)?.public_key()`) equals the leaf's SPKI
   (`x509_parser`). This covers certbot (`fullchain.pem` + `privkey.pem`), `.crt` + `.key`, and cert+key in one file.
4. For each pair: `not_before`, `not_after`, SAN DNS names (lowercase; CN used only if there is no SAN extension).
5. Ignored with `warn!` (never fatal): unreadable file, unparsable PEM, key without certificate, certificate without key,
   unsupported key type. Expired pairs are **kept** in the index (needed by T7) but marked expired.

```rust
pub struct LocalCert { pub key: Arc<CertifiedKey>, pub names: Vec<String>, pub not_before: i64, pub not_after: i64, pub source: PathBuf }
pub struct LocalIndex { certs: Vec<LocalCert> }
impl LocalIndex {
    pub fn load(dir: &Path) -> LocalIndex;                     // never fails: bad files are skipped
    pub fn from_pems(files: &[(PathBuf, Vec<u8>)]) -> LocalIndex;  // pure, used by tests
    /// Best certificate covering `host` that is valid at `now`: exact SAN or single-label wildcard;
    /// among several, the one expiring last.
    pub fn best_valid(&self, host: &str, now: i64) -> Option<&LocalCert>;
    /// Same, ignoring validity, most recent `not_after` first (last resort, T7).
    pub fn best_any(&self, host: &str) -> Option<&LocalCert>;
}
```
Wildcard matching follows the routing rule (`plans/04`): `*.a.com` covers `x.a.com`, not `a.com` nor `x.y.a.com`.
A route host that is itself a wildcard (`*.a.com`) is covered only by a certificate whose SAN contains `*.a.com`.

### 3.2 Reloading

`LocalIndex` is rebuilt (and the selection of §4 re-run) when:
* the configuration is reloaded (SIGHUP or file change, `plans/02` §7);
* the content of `certs-dir` changes: the existing 2 s watcher also computes a stamp of the directory
  (sorted list of `(file name, mtime, len)`) and triggers a **TLS-only** reconcile when it changes.
  Certbot renewals are therefore picked up without restarting or reloading.

A reconcile never removes a working certificate because a file is temporarily unreadable: an empty or failing index
for a host keeps the currently installed key and records an incident (same rule as a failed config reload).

## 4. Certificate selection per host (auto mode)

`fn select(host, now) -> Selected` is a **pure** function of: the local index, the ACME certificate stored in SQLite
for this host (if any, with its `not_after`), and whether a self-signed key is already installed.

Order (first match wins):

| # | Candidate | Source label |
|---|---|---|
| 1 | local certificate valid at `now` (`best_valid`) | `local` |
| 2 | ACME certificate valid at `now` (from the database) | `acme` |
| 3 | expired local certificate (`best_any`) **only if** step 2 found nothing (T7) | `local-expired` |
| 4 | temporary self-signed certificate (generated, covers all hosts of the route still unserved) | `self-signed` |

* The selected key is installed in the resolver with `CertResolver::set(host, key)` (exact host) or
  `set_wildcard(parent, key)` (wildcard host). The resolver API from `plans/07` §3 is unchanged.
* When the label of a host changes compared to the previous selection: `warn!(host, from, to, "tls certificate source changed")`
  and `recorder.record(Incident { kind: "tls_fallback", detail: "host=<h> <from> -> <to> not_after=<rfc3339>" })`.
  The first selection at startup is logged at `info!` only (no incident).
* `default-cert` keeps working: it points to whatever key is selected for that host.
* Selection runs: at startup, after every reconcile (§3.2), and after every ACME issuance or renewal (worker).
  It also runs on the worker's 60 s tick so that an expiring local certificate is replaced **at** its `not_after`
  (expiry is a time event, not a file event).

## 5. ACME in auto mode (replaces `plans/07` §8)

### 5.1 When ACME is possible for a route

`AcmeTarget` is `Some` only if **all** hold: an email is available (`tls email=` or `gateway.default-email`),
no host of the route is a wildcard, and the gateway has an HTTPS listener. Otherwise `acme = None`.

Config validation (`paasers check`):
* host with `acme = None` and **no** local certificate covering it (valid or expired) in `certs-dir` at load
  ⇒ **error** `route <id>: host <h> has no local certificate and ACME is impossible (<reason>)`.
* host with `acme = None` but a local certificate ⇒ **warning** `no ACME fallback for <h>: renew the local certificate before <date>`.
  (`paasers check` prints warnings on stderr and still exits 0.)
* `certs-dir` unset and `acme = None` ⇒ error, as above.

### 5.2 Directory and account per route

* `directory = if staging { LetsEncrypt::Staging } else { gateway.acme-directory }`.
  `staging` therefore forces Let's Encrypt staging even if the global directory is a custom URL.
* Accounts are already stored per directory URL (`acme_account` table): production and staging accounts coexist
  without schema change. `CertManager` keeps one `Account` per directory URL (lazy, `HashMap<String, Account>`).
* Certificates stay stored per **domain** in `certs`. A route switching from staging to production (or back)
  must not keep serving a certificate from the other CA: the `certs` table gains a column (additive migration v2):
  `ALTER TABLE certs ADD COLUMN directory TEXT NOT NULL DEFAULT ''`. A stored certificate whose `directory` differs
  from the route's current directory is ignored by the selection and triggers a new issuance.

### 5.3 When the worker issues (proactive, T6)

`TlsJob` gains `directory: String`. For each job, per host, `needs_issue(host)` is true when **no** valid
certificate from a source at least as preferred will cover the host for 30 more days:
```text
needs_issue(host) =
     local_valid_until(host) < now + 30d          // no local cert, or it expires within 30 days
  && acme_valid_until(host, directory) < now + 30d   // no usable ACME cert, or it needs renewal
```
A job is issued when `needs_issue` holds for at least one of its hosts; the order covers **all** hosts of the
route (one certificate, SANs = hosts, unchanged). Backoff, sequential issuance and incidents are unchanged
(`plans/07` §8.2).

Consequence (accepted, T6): an operator who renews the local certificate inside the 30-day window may have
caused one useless Let's Encrypt issuance. The local certificate wins again as soon as it is reloaded (§4 step 1).

## 6. Self-signed mode

* At startup and at each reconcile, one certificate per route is generated with `rcgen` covering all its hosts
  (wildcards included), validity 1 year, **kept in memory only** (new key on every restart, accepted).
* Never stored in SQLite, never replaced by ACME, `certs-dir` ignored for this route.
* Regenerated only when the route's host list changes or when it is within 30 days of expiry (worker tick).

## 7. Observability (changes to `plans/11` §4.1)

`certificates` entries of `get_route_status` become:
```json
{"domain":"client.com","source":"local","not_after":"2026-12-29T00:00:00.000Z","days_left":88,
 "path":"/etc/paasers/certs/fullchain.pem","acme_directory":null}
```
`source` ∈ `local` | `acme` | `local-expired` | `self-signed`; `path` only for local sources;
`acme_directory` only for `acme`. The old boolean `self_signed` is removed.
`inspect_incident` hint for `tls_fallback`: "Certificate source changed for this host: check certs-dir and ACME."

## 8. Changes to other plans (already applied in the documents)

* `plans/01` §3.2: new `certs-dir`; §3.8 replaced by a pointer to this plan; §5 validation rules 4 and 7 updated;
  §8 tests updated.
* `plans/07`: §8.1 file mode removed (points here); `TlsJob` gains `directory`.
* `plans/03` §4: migration v2 (`certs.directory`).
* `plans/11` §4.1: `certificates` shape.
* `plans/12`: `tests/tls.rs` and `tests/specs_example.rs` use `certs-dir` instead of `cert-file`.
* `PLAN.md`: D21, D22, edge case 11, R4, §7 phase table.

## 9. Tests

Unit (`tls/local.rs`, pure via `from_pems`, certificates built with `rcgen`):
- `pairs_key_and_cert_across_files` (certbot layout), `pairs_cert_and_key_in_one_file`, `ignores_orphans_and_garbage`.
- `best_valid_exact_and_wildcard` (`*.a.com` covers `x.a.com`, not `a.com`, not `x.y.a.com`), `best_valid_prefers_latest_expiry`,
  `expired_excluded_from_valid_but_kept_for_any`, `not_yet_valid_excluded`.
- `cn_used_only_without_san`.

Unit (selection, pure):
- `select_local_first`, `select_acme_when_local_expired`, `select_expired_local_when_no_acme` (T7),
  `select_self_signed_when_nothing`, `source_change_reports_from_to`, `acme_cert_from_other_directory_ignored`.
- `needs_issue_matrix`: no local + no acme ⇒ true; local valid 60 d ⇒ false; local valid 10 d + no acme ⇒ true;
  local valid 10 d + acme valid 80 d ⇒ false; local expired + acme valid 80 d ⇒ false.

Unit (config):
- `tls_auto_defaults` (staging false, acme Some with default-email), `tls_staging_child`, `tls_self_signed`,
  `self_signed_with_email_rejected`, `self_signed_with_staging_rejected`, `cert_file_removed_with_hint`,
  `wildcard_without_local_cert_rejected`, `no_email_without_local_cert_rejected`, `no_email_with_local_cert_warns`,
  `certs_dir_must_be_directory`, `redirect_https_default_true_for_all_modes`.

Integration (`tests/tls.rs`, rewritten):
- `local_cert_served_by_sni` (CA + leaf written to a temp `certs-dir`, h2 + h1 over TLS, unknown SNI rejected).
- `wildcard_local_cert_served`.
- `certs_dir_change_is_picked_up` (replace the files with a new leaf ⇒ new serial served within 5 s, no config reload).
- `expired_local_switches_to_acme_cert` (stored ACME certificate inserted in the DB for the domain + expired local
  certificate ⇒ the ACME one is served, `tls_fallback` incident recorded).
- `expired_local_kept_when_acme_fails` (unreachable directory ⇒ the expired local certificate is still presented).
- `self_signed_route_serves_generated_cert` (issuer == subject, SANs = hosts, wildcard host included).
- `acme_route_serves_self_signed_before_issuance` (kept).

Staging:
- Unit `directory_for_route`: route with `staging` ⇒ Let's Encrypt staging URL even when the global
  `acme-directory` is production or a custom URL; route without `staging` ⇒ the global directory.
- `tests/acme.rs` (`#[ignore]`, pebble) is unchanged: it exercises the global `acme-directory` path.
  Real Let's Encrypt staging cannot run in CI and stays a manual test (`plans/12` §9).

## 10. DoD P13
- [x] §9 tests green, `cargo check` / `cargo test` / `cargo clippy --all-targets -- -D warnings` green, with and
      without `--no-default-features`; `scripts/ci.sh` green.
- [x] `examples/gateway.kdl` and `tests/fixtures/specs_verbatim.kdl` still parse (they only use `tls email=`).
- [x] README "Configuration reference" and "Known limitations" updated. Commit `P13: tls modes`.
