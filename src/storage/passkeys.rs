//! WebAuthn passkey records per route.
use super::{Db, StorageError, now_unix};

pub const MAX_PASSKEYS_PER_ROUTE: i64 = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRecord {
    pub id: i64,
    pub cred_id: Vec<u8>,
    pub passkey_json: String,
    pub label: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

impl Db {
    pub async fn list_passkeys(&self, route: &str) -> Result<Vec<PasskeyRecord>, StorageError> {
        let route = route.to_string();
        self.call(move |c| {
            let mut st = c.prepare(
                "SELECT id, cred_id, passkey_json, label, created_at, last_used_at FROM passkeys WHERE route_id = ?1 ORDER BY id",
            )?;
            st.query_map([&route], |r| {
                Ok(PasskeyRecord {
                    id: r.get(0)?,
                    cred_id: r.get(1)?,
                    passkey_json: r.get(2)?,
                    label: r.get(3)?,
                    created_at: r.get(4)?,
                    last_used_at: r.get(5)?,
                })
            })?
            .collect()
        })
        .await
    }

    /// Count and insert in one closure on the single SQLite thread, so the limit is atomic.
    pub async fn add_passkey(
        &self,
        route: &str,
        cred_id: &[u8],
        passkey_json: &str,
        label: &str,
    ) -> Result<(), StorageError> {
        let (route, cred, json, label) = (
            route.to_string(),
            cred_id.to_vec(),
            passkey_json.to_string(),
            label.to_string(),
        );
        let inserted = self
            .call(move |c| {
                let n: i64 = c.query_row("SELECT COUNT(*) FROM passkeys WHERE route_id = ?1", [&route], |r| r.get(0))?;
                if n >= MAX_PASSKEYS_PER_ROUTE {
                    return Ok(false);
                }
                c.execute(
                    "INSERT INTO passkeys(route_id, cred_id, passkey_json, label, created_at) VALUES(?1,?2,?3,?4,?5)",
                    (&route, &cred, &json, &label, now_unix()),
                )?;
                Ok(true)
            })
            .await?;
        if inserted {
            Ok(())
        } else {
            Err(StorageError::LimitReached("passkeys per route"))
        }
    }

    /// Stores the updated credential state (for example the signature counter) and the last use time.
    pub async fn update_passkey(&self, cred_id: &[u8], passkey_json: &str) -> Result<(), StorageError> {
        let (cred, json) = (cred_id.to_vec(), passkey_json.to_string());
        self.call(move |c| {
            c.execute(
                "UPDATE passkeys SET passkey_json = ?2, last_used_at = ?3 WHERE cred_id = ?1",
                (&cred, &json, now_unix()),
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
    async fn passkey_crud_and_limit() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("c.db")).await.unwrap();
        db.add_passkey("a.com", b"c1", "{}", "laptop").await.unwrap();
        let l = db.list_passkeys("a.com").await.unwrap();
        assert_eq!(
            (l.len(), l[0].label.as_str(), l[0].last_used_at),
            (1, "laptop", None)
        );
        db.update_passkey(b"c1", "{\"n\":1}").await.unwrap();
        let l = db.list_passkeys("a.com").await.unwrap();
        assert_eq!(l[0].passkey_json, "{\"n\":1}");
        assert!(l[0].last_used_at.is_some());
        assert!(db.list_passkeys("b.com").await.unwrap().is_empty());
        // Duplicate credential ids are rejected by the UNIQUE constraint.
        assert!(db.add_passkey("a.com", b"c1", "{}", "dup").await.is_err());
        for i in 1..MAX_PASSKEYS_PER_ROUTE {
            db.add_passkey("a.com", format!("k{i}").as_bytes(), "{}", "x")
                .await
                .unwrap();
        }
        let e = db.add_passkey("a.com", b"overflow", "{}", "x").await.unwrap_err();
        assert!(matches!(e, StorageError::LimitReached(_)));
        db.add_passkey("b.com", b"other", "{}", "x").await.unwrap();
    }
}
