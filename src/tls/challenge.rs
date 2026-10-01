//! HTTP-01 challenge responses, shared between the ACME worker and the HTTP listener.
use std::collections::HashMap;
use std::sync::{PoisonError, RwLock};

#[derive(Default)]
pub struct ChallengeStore {
    inner: RwLock<HashMap<String, String>>,
}

/// ACME tokens are base64url: anything else is never served.
pub fn valid_token(t: &str) -> bool {
    !t.is_empty()
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl ChallengeStore {
    pub fn put(&self, token: String, key_authorization: String) {
        self.inner
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(token, key_authorization);
    }

    pub fn get(&self, token: &str) -> Option<String> {
        if !valid_token(token) {
            return None;
        }
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(token)
            .cloned()
    }

    pub fn remove(&self, token: &str) {
        self.inner
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_remove() {
        let s = ChallengeStore::default();
        assert!(s.get("tok").is_none());
        s.put("tok".into(), "tok.thumb".into());
        assert_eq!(s.get("tok").as_deref(), Some("tok.thumb"));
        s.remove("tok");
        assert!(s.get("tok").is_none());
    }

    #[test]
    fn invalid_tokens_are_never_served() {
        let s = ChallengeStore::default();
        s.put("../etc".into(), "x".into());
        assert!(s.get("../etc").is_none() && s.get("").is_none());
        assert!(valid_token("aZ09_-") && !valid_token("a b"));
    }
}
