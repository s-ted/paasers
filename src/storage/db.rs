//! SQLite thread, job loop and migrations.
use super::StorageError;
use std::path::Path;

type Job = Box<dyn FnOnce(&mut rusqlite::Connection) + Send>;

const MIGRATIONS: &[&str] = &["CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS secrets (name TEXT PRIMARY KEY, value BLOB NOT NULL);
   CREATE TABLE IF NOT EXISTS acme_account (directory TEXT PRIMARY KEY, credentials TEXT NOT NULL, created_at INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS certs (domain TEXT PRIMARY KEY, cert_pem TEXT NOT NULL, key_pem TEXT NOT NULL,
                                     not_after INTEGER NOT NULL, issued_at INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS passkeys (id INTEGER PRIMARY KEY AUTOINCREMENT, route_id TEXT NOT NULL,
                                        cred_id BLOB NOT NULL UNIQUE, passkey_json TEXT NOT NULL, label TEXT NOT NULL,
                                        created_at INTEGER NOT NULL, last_used_at INTEGER);
   CREATE INDEX IF NOT EXISTS passkeys_route ON passkeys(route_id);"];

/// Cloneable handle to the SQLite thread. The thread stops when the last handle is dropped.
#[derive(Clone)]
pub struct Db {
    tx: tokio::sync::mpsc::Sender<Job>,
}

fn schema_version(c: &rusqlite::Connection) -> Result<usize, StorageError> {
    let has_meta: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta')",
        [],
        |r| r.get(0),
    )?;
    if !has_meta {
        return Ok(0);
    }
    let v: Option<String> = c
        .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| {
            r.get(0)
        })
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })?;
    match v {
        None => Ok(0),
        Some(s) => s
            .parse()
            .map_err(|_| StorageError::Corrupt(format!("bad schema_version `{s}`"))),
    }
}

fn run_migrations(c: &mut rusqlite::Connection) -> Result<(), StorageError> {
    let version = schema_version(c)?;
    if version > MIGRATIONS.len() {
        return Err(StorageError::Corrupt(
            "database created by a newer paasers".into(),
        ));
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(version) {
        let tx = c.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?1)",
            [(i + 1).to_string()],
        )?;
        tx.commit()?;
    }
    Ok(())
}

fn open_connection(path: &Path) -> Result<rusqlite::Connection, StorageError> {
    let mut c = rusqlite::Connection::open(path)?;
    c.pragma_update(None, "journal_mode", "WAL")?;
    c.pragma_update(None, "synchronous", "NORMAL")?;
    c.pragma_update(None, "foreign_keys", "ON")?;
    c.busy_timeout(std::time::Duration::from_secs(5))?;
    run_migrations(&mut c)?;
    Ok(c)
}

impl Db {
    pub async fn open(path: &Path) -> Result<Db, StorageError> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        if let Some(p) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(p)?;
        }
        if !path.exists() {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Job>(256);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<(), StorageError>>();
        let path = path.to_owned();
        std::thread::Builder::new().name("sqlite".into()).spawn(move || {
            let mut conn = match open_connection(&path) {
                Ok(c) => {
                    let _ = ready_tx.send(Ok(()));
                    c
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            while let Some(job) = rx.blocking_recv() {
                job(&mut conn);
            }
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        })?;
        ready_rx.await.map_err(|_| StorageError::Closed)??;
        Ok(Db { tx })
    }

    /// Runs `f` on the SQLite thread and returns its result.
    pub async fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut rusqlite::Connection) -> Result<R, rusqlite::Error> + Send + 'static,
    ) -> Result<R, StorageError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx
            .send(Box::new(move |c| {
                let _ = tx.send(f(c));
            }))
            .await
            .map_err(|_| StorageError::Closed)?;
        Ok(rx.await.map_err(|_| StorageError::Closed)??)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn open_creates_file_0600_and_wal() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub/certs.db");
        let db = Db::open(&p).await.unwrap();
        let mode: String = db
            .call(|c| c.query_row("PRAGMA journal_mode", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(mode, "wal");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(p.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[tokio::test]
    async fn migrations_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.db");
        drop(Db::open(&p).await.unwrap());
        let db = Db::open(&p).await.unwrap();
        let v: String = db
            .call(|c| {
                c.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| {
                    r.get(0)
                })
            })
            .await
            .unwrap();
        assert_eq!(v, "1");
    }

    #[tokio::test]
    async fn newer_schema_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.db");
        let db = Db::open(&p).await.unwrap();
        db.call(|c| c.execute("UPDATE meta SET value='99' WHERE key='schema_version'", []))
            .await
            .unwrap();
        drop(db);
        // Let the sqlite thread flush and exit before reopening.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(matches!(Db::open(&p).await, Err(StorageError::Corrupt(_))));
    }

    #[tokio::test]
    async fn open_fails_on_directory_path() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Db::open(dir.path()).await.is_err());
    }
}
