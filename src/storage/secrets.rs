//! Persistent random secrets (for example the gatekeeper session key).
use super::{Db, StorageError};

impl Db {
    /// Returns the secret `name`, creating `len` random bytes on first use.
    pub async fn get_or_create_secret(&self, name: &str, len: usize) -> Result<Vec<u8>, StorageError> {
        let name = name.to_string();
        self.call(move |c| {
            let fresh: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
            c.execute(
                "INSERT OR IGNORE INTO secrets(name, value) VALUES(?1, ?2)",
                (&name, &fresh),
            )?;
            c.query_row("SELECT value FROM secrets WHERE name = ?1", [&name], |r| r.get(0))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn secret_stable_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c.db");
        let db = Db::open(&p).await.unwrap();
        let a = db.get_or_create_secret("session-hmac", 32).await.unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(db.get_or_create_secret("session-hmac", 32).await.unwrap(), a);
        drop(db);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let db = Db::open(&p).await.unwrap();
        assert_eq!(db.get_or_create_secret("session-hmac", 32).await.unwrap(), a);
        assert_ne!(db.get_or_create_secret("other", 32).await.unwrap(), a);
    }
}
