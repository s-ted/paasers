//! Certificate records.
use super::{Db, StorageError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRecord {
    pub domain: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub not_after: i64,
    pub issued_at: i64,
}

impl Db {
    pub async fn list_certs(&self) -> Result<Vec<CertRecord>, StorageError> {
        self.call(|c| {
            let mut st = c.prepare(
                "SELECT domain, cert_pem, key_pem, not_after, issued_at FROM certs ORDER BY domain",
            )?;
            st.query_map([], |r| {
                Ok(CertRecord {
                    domain: r.get(0)?,
                    cert_pem: r.get(1)?,
                    key_pem: r.get(2)?,
                    not_after: r.get(3)?,
                    issued_at: r.get(4)?,
                })
            })?
            .collect()
        })
        .await
    }

    pub async fn get_cert(&self, domain: &str) -> Result<Option<CertRecord>, StorageError> {
        let d = domain.to_string();
        self.call(move |c| {
            let mut st =
                c.prepare("SELECT cert_pem, key_pem, not_after, issued_at FROM certs WHERE domain = ?1")?;
            let mut rows = st.query_map([&d], |r| {
                Ok(CertRecord {
                    domain: d.clone(),
                    cert_pem: r.get(0)?,
                    key_pem: r.get(1)?,
                    not_after: r.get(2)?,
                    issued_at: r.get(3)?,
                })
            })?;
            rows.next().transpose()
        })
        .await
    }

    pub async fn put_cert(&self, rec: CertRecord) -> Result<(), StorageError> {
        self.call(move |c| {
            c.execute(
                "INSERT INTO certs(domain, cert_pem, key_pem, not_after, issued_at) VALUES(?1,?2,?3,?4,?5)
                 ON CONFLICT(domain) DO UPDATE SET cert_pem=excluded.cert_pem, key_pem=excluded.key_pem,
                                                   not_after=excluded.not_after, issued_at=excluded.issued_at",
                (&rec.domain, &rec.cert_pem, &rec.key_pem, rec.not_after, rec.issued_at),
            )
            .map(|_| ())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(d: &str, na: i64) -> CertRecord {
        CertRecord {
            domain: d.into(),
            cert_pem: "C".into(),
            key_pem: "K".into(),
            not_after: na,
            issued_at: 1,
        }
    }

    #[tokio::test]
    async fn cert_upsert_and_get() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("c.db")).await.unwrap();
        assert!(db.get_cert("a.com").await.unwrap().is_none());
        db.put_cert(rec("a.com", 10)).await.unwrap();
        db.put_cert(rec("a.com", 20)).await.unwrap();
        assert_eq!(db.get_cert("a.com").await.unwrap(), Some(rec("a.com", 20)));
    }

    #[tokio::test]
    async fn list_certs_multiple() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("c.db")).await.unwrap();
        db.put_cert(rec("b.com", 1)).await.unwrap();
        db.put_cert(rec("a.com", 2)).await.unwrap();
        let all = db.list_certs().await.unwrap();
        assert_eq!(
            all.iter().map(|r| r.domain.as_str()).collect::<Vec<_>>(),
            vec!["a.com", "b.com"]
        );
    }
}
