//! Argon2id PSK verification, off the async runtime and bounded by a semaphore.
use std::sync::Arc;
use tokio::sync::Semaphore;

const MAX_PASSWORD_BYTES: usize = 1024;

pub fn verify_blocking(phc: &str, candidate: &str) -> bool {
    use argon2::password_hash::PasswordVerifier;
    candidate.len() <= MAX_PASSWORD_BYTES
        && argon2::Argon2::default()
            .verify_password(candidate.as_bytes(), phc)
            .is_ok()
}

pub async fn verify_psk(sem: &Semaphore, phc: Arc<str>, candidate: String) -> bool {
    if candidate.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    let Ok(_permit) = sem.acquire().await else {
        return false;
    };
    tokio::task::spawn_blocking(move || verify_blocking(&phc, &candidate))
        .await
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const HASH: &str =
        "$argon2id$v=19$m=19456,t=2,p=1$ftC9LdPXCcZ6MiQpvWUwXA$haZvTFqngv2fUrBLJTBmAw2Ltxdy9HonzbKTkg4bXhI";

    #[tokio::test]
    async fn verify_fixture_hash() {
        let sem = Semaphore::new(2);
        assert!(verify_psk(&sem, Arc::from(HASH), "preview".into()).await);
    }

    #[tokio::test]
    async fn wrong_password() {
        let sem = Semaphore::new(2);
        assert!(!verify_psk(&sem, Arc::from(HASH), "Preview".into()).await);
        assert!(!verify_psk(&sem, Arc::from("not a hash"), "preview".into()).await);
    }

    #[tokio::test]
    async fn oversized_password_rejected() {
        let sem = Semaphore::new(2);
        assert!(!verify_psk(&sem, Arc::from(HASH), "a".repeat(2000)).await);
    }
}
