# P3: SQLite storage (`src/storage/`)

## 1. Principle

* `rusqlite` is **synchronous**: a single `Connection` owned by **a dedicated OS thread** (`std::thread::spawn`), which receives commands via `tokio::sync::mpsc::Sender<Job>` and replies via `oneshot`. No SQLite call on a tokio worker. No pool (rare writes, reads at startup/reload).
* WAL mode, `synchronous=NORMAL`, `busy_timeout=5000`, `foreign_keys=ON`.
* File created with permissions 0600 (create the file via `std::fs::OpenOptions` + `std::os::unix::fs::OpenOptionsExt::mode(0o600)` **before** `Connection::open` if it does not exist). Parent directory created (`create_dir_all`) with 0700.

## 2. Files

| File | Content |
|---|---|
| `storage/mod.rs` | `Db` (cloneable handle), `StorageError`, `open()` |
| `storage/db.rs` | SQLite thread, job loop, migrations |
| `storage/certs.rs` | `CertRecord`, `get_cert`, `put_cert`, `list_certs` |
| `storage/secrets.rs` | `get_or_create_secret(name, len)` |
| `storage/acme.rs` | `get_account(directory)`, `put_account` |
| `storage/passkeys.rs` | `list_passkeys(route)`, `add_passkey`, `update_passkey`, `touch_passkey` |

## 3. API

```rust
#[derive(Clone)]
pub struct Db { tx: tokio::sync::mpsc::Sender<Job> }
type Job = Box<dyn FnOnce(&mut rusqlite::Connection) + Send>;

impl Db {
    pub async fn open(path: &Path) -> Result<Db, StorageError>;
    /// Runs `f` on the SQLite thread and returns its result.
    pub async fn call<R: Send + 'static>(
        &self, f: impl FnOnce(&mut rusqlite::Connection) -> Result<R, rusqlite::Error> + Send + 'static,
    ) -> Result<R, StorageError>;
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("sqlite: {0}")] Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")] Io(#[from] std::io::Error),
    #[error("storage thread stopped")] Closed,
    #[error("corrupt record: {0}")] Corrupt(String),
    #[error("limit reached: {0}")] LimitReached(&'static str),
}
```
Implementation **validated** (compiled, strict clippy OK, WAL + 0600 test OK); add `run_migrations(&mut c)?` and `foreign_keys` in the open closure:

```rust
impl Db {
    pub async fn open(path: &Path) -> Result<Db, StorageError> {
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(p) = path.parent() { std::fs::create_dir_all(p)?; }
        if !path.exists() { std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?; }
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Job>(256);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<(), StorageError>>();
        let path = path.to_owned();
        std::thread::Builder::new().name("sqlite".into()).spawn(move || {
            let conn = rusqlite::Connection::open(&path).map_err(StorageError::from).and_then(|mut c| {
                c.pragma_update(None, "journal_mode", "WAL")?;
                c.pragma_update(None, "synchronous", "NORMAL")?;
                c.pragma_update(None, "foreign_keys", "ON")?;
                c.busy_timeout(std::time::Duration::from_secs(5))?;
                run_migrations(&mut c)?;           // -> Result<(), StorageError>
                Ok(c)
            });
            let mut conn = match conn {
                Ok(c) => { let _ = ready_tx.send(Ok(())); c }
                Err(e) => { let _ = ready_tx.send(Err(e)); return; }
            };
            while let Some(job) = rx.blocking_recv() { job(&mut conn); }
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        })?;
        ready_rx.await.map_err(|_| StorageError::Closed)??;
        Ok(Db { tx })
    }
    pub async fn call<R: Send + 'static>(
        &self, f: impl FnOnce(&mut rusqlite::Connection) -> Result<R, rusqlite::Error> + Send + 'static,
    ) -> Result<R, StorageError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx.send(Box::new(move |c| { let _ = tx.send(f(c)); })).await.map_err(|_| StorageError::Closed)?;
        Ok(rx.await.map_err(|_| StorageError::Closed)??)
    }
}
```
The thread stops when the last `Db` (hence the last `Sender`) is dropped.

## 4. Migrations (`db.rs`)

```rust
const MIGRATIONS: &[&str] = &[
  // v1
  "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS secrets (name TEXT PRIMARY KEY, value BLOB NOT NULL);
   CREATE TABLE IF NOT EXISTS acme_account (directory TEXT PRIMARY KEY, credentials TEXT NOT NULL, created_at INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS certs (domain TEXT PRIMARY KEY, cert_pem TEXT NOT NULL, key_pem TEXT NOT NULL,
                                     not_after INTEGER NOT NULL, issued_at INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS passkeys (id INTEGER PRIMARY KEY AUTOINCREMENT, route_id TEXT NOT NULL,
                                        cred_id BLOB NOT NULL UNIQUE, passkey_json TEXT NOT NULL, label TEXT NOT NULL,
                                        created_at INTEGER NOT NULL, last_used_at INTEGER);
   CREATE INDEX IF NOT EXISTS passkeys_route ON passkeys(route_id);",
];
```
Procedure: read `meta.schema_version` (absent = 0); for each migration with index ≥ version, in a transaction: `execute_batch(sql)` then `INSERT OR REPLACE INTO meta VALUES('schema_version', ?)`. Version in database > `MIGRATIONS.len()` ⇒ `StorageError::Corrupt("database created by a newer paasers")` (the binary refuses to start: protects against incompatible rollback).

All timestamps = Unix seconds (`i64`) via `SystemTime::now().duration_since(UNIX_EPOCH)`, function `storage::now_unix() -> i64` (returns 0 if the clock is before epoch, never panics).

## 5. Queries (exact)

```sql
-- certs
SELECT domain, cert_pem, key_pem, not_after, issued_at FROM certs;
SELECT cert_pem, key_pem, not_after, issued_at FROM certs WHERE domain = ?1;
INSERT INTO certs(domain, cert_pem, key_pem, not_after, issued_at) VALUES(?1,?2,?3,?4,?5)
  ON CONFLICT(domain) DO UPDATE SET cert_pem=excluded.cert_pem, key_pem=excluded.key_pem,
                                    not_after=excluded.not_after, issued_at=excluded.issued_at;
-- secrets
SELECT value FROM secrets WHERE name = ?1;
INSERT OR IGNORE INTO secrets(name, value) VALUES(?1, ?2);   -- then re-SELECT (handles the race)
-- acme
SELECT credentials FROM acme_account WHERE directory = ?1;
INSERT OR REPLACE INTO acme_account(directory, credentials, created_at) VALUES(?1,?2,?3);
-- passkeys
SELECT id, cred_id, passkey_json, label, created_at, last_used_at FROM passkeys WHERE route_id = ?1 ORDER BY id;
INSERT INTO passkeys(route_id, cred_id, passkey_json, label, created_at) VALUES(?1,?2,?3,?4,?5);
UPDATE passkeys SET passkey_json = ?2, last_used_at = ?3 WHERE cred_id = ?1;
SELECT COUNT(*) FROM passkeys WHERE route_id = ?1;
```
Limit: 20 passkeys max per route: `add_passkey` does the `COUNT(*)` then the `INSERT` **within the same `call` closure** (hence atomic, single thread). The closure returns `Ok(false)` if the limit is reached (it can only return `rusqlite::Error`), and `add_passkey` converts `false` into `Err(StorageError::LimitReached("passkeys per route"))`.

A **single** certificate per domain: for a route with several hosts, a single ACME order covers all hosts (SAN) and the same `(cert_pem, key_pem)` is written under **each** domain (simple lookup by SNI).

## 6. Secrets

`get_or_create_secret("session-hmac", 32)`: if absent, generates `rand::random::<[u8; 32]>()`, `INSERT OR IGNORE`, re-reads. Used by the gatekeeper (P9).

## 7. Tests (`tempfile::tempdir()`)

- `open_creates_file_0600_and_wal` (checks `PRAGMA journal_mode` = `wal`, file mode `0o600` via `metadata().permissions().mode() & 0o777`).
- `migrations_idempotent` (open twice).
- `newer_schema_refused` (write `schema_version=99` then reopen ⇒ `Corrupt`).
- `cert_upsert_and_get`, `list_certs_multiple`.
- `secret_stable_across_reopen`.
- `acme_account_roundtrip`.
- `passkey_crud_and_limit`.
- `open_fails_on_directory_path` (path = an existing directory ⇒ `Err`, no panic).

## 8. DoD P3
- [ ] `cargo test storage::` green. Commit `P3: storage`.
