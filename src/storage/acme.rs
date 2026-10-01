//! ACME account credentials per directory.
use super::{Db, StorageError, now_unix};

impl Db {
    pub async fn get_account(&self, directory: &str) -> Result<Option<String>, StorageError> {
        let d = directory.to_string();
        self.call(move |c| {
            let mut st = c.prepare("SELECT credentials FROM acme_account WHERE directory = ?1")?;
            let mut rows = st.query_map([&d], |r| r.get::<_, String>(0))?;
            rows.next().transpose()
        })
        .await
    }

    pub async fn put_account(&self, directory: &str, credentials: &str) -> Result<(), StorageError> {
        let (d, cr) = (directory.to_string(), credentials.to_string());
        self.call(move |c| {
            c.execute(
                "INSERT OR REPLACE INTO acme_account(directory, credentials, created_at) VALUES(?1,?2,?3)",
                (&d, &cr, now_unix()),
            )
            .map(|_| ())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn acme_account_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("c.db")).await.unwrap();
        assert!(db.get_account("prod").await.unwrap().is_none());
        db.put_account("prod", "{\"id\":1}").await.unwrap();
        db.put_account("prod", "{\"id\":2}").await.unwrap();
        assert_eq!(
            db.get_account("prod").await.unwrap().as_deref(),
            Some("{\"id\":2}")
        );
        assert!(db.get_account("staging").await.unwrap().is_none());
    }
}
