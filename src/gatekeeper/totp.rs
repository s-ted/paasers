//! TOTP verification with replay protection.
use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

const KEEP_STEPS: usize = 8;

pub struct TotpChecker {
    totp: totp_rs::Totp,
    used: Mutex<VecDeque<u64>>,
}

impl TotpChecker {
    pub fn new(secret: &[u8]) -> Option<Self> {
        let totp = totp_rs::Builder::new()
            .with_secret(secret.to_vec())
            .build()
            .ok()?;
        Some(Self {
            totp,
            used: Mutex::new(VecDeque::new()),
        })
    }

    /// Accepts a 6-digit code (spaces ignored) once per time step (skew of one step).
    pub fn verify(&self, code: &str, now_unix: u64) -> bool {
        let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        let Some(step) = self.totp.check(&code, now_unix) else {
            return false;
        };
        let mut used = self.used.lock().unwrap_or_else(PoisonError::into_inner);
        if used.contains(&step) {
            return false;
        }
        used.push_back(step);
        while used.len() > KEEP_STEPS {
            used.pop_front();
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"12345678901234567890";

    fn code(t: u64) -> String {
        totp_rs::Builder::new()
            .with_secret(SECRET.to_vec())
            .build()
            .unwrap()
            .generate(t)
            .to_string()
    }

    #[test]
    fn valid_code_then_replay_rejected() {
        let c = TotpChecker::new(SECRET).unwrap();
        let t = 1_700_000_000;
        assert!(c.verify(&code(t), t));
        assert!(!c.verify(&code(t), t), "same step must not be accepted twice");
        assert!(c.verify(&code(t + 30), t + 30), "next step is fine");
    }

    #[test]
    fn wrong_code() {
        let c = TotpChecker::new(SECRET).unwrap();
        assert!(!c.verify("000000", 1_700_000_000) || code(1_700_000_000) == "000000");
        assert!(!c.verify(&code(1_000_000_000), 1_700_000_000));
    }

    #[test]
    fn non_digit_rejected() {
        let c = TotpChecker::new(SECRET).unwrap();
        for s in ["", "12345", "1234567", "12a456", "１２３４５６"] {
            assert!(!c.verify(s, 1_700_000_000), "{s:?}");
        }
    }

    #[test]
    fn spaces_are_ignored() {
        let c = TotpChecker::new(SECRET).unwrap();
        let t = 1_700_000_100;
        let k = code(t);
        assert!(c.verify(&format!("{} {}", &k[..3], &k[3..]), t));
    }
}
