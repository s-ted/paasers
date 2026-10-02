//! Helper subcommands: password hash, API key hash and TOTP secret generation.
use std::io::Read;
use std::process::ExitCode;

fn read_first_line() -> String {
    let mut s = String::new();
    let _ = std::io::stdin().read_to_string(&mut s);
    s.lines().next().unwrap_or("").to_string()
}

pub fn hash_password_str(pw: &str) -> Result<String, String> {
    use argon2::password_hash::PasswordHasher;
    if pw.is_empty() {
        return Err("empty password".into());
    }
    if pw.chars().count() < 8 {
        return Err("password must be at least 8 characters".into());
    }
    let params = argon2::Params::new(19456, 2, 1, None).map_err(|e| e.to_string())?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let salt: [u8; 16] = rand::random();
    let h = a
        .hash_password_with_salt(pw.as_bytes(), &salt)
        .map_err(|e| e.to_string())?;
    Ok(h.to_string())
}

pub fn hash_password() -> ExitCode {
    match hash_password_str(&read_first_line()) {
        Ok(h) => {
            println!("{h}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

pub fn api_key_hex(key: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(key.as_bytes()))
}

pub fn hash_api_key() -> ExitCode {
    let key = read_first_line();
    if key.is_empty() {
        eprintln!("error: empty key");
        return ExitCode::from(2);
    }
    println!("{}", api_key_hex(&key));
    ExitCode::SUCCESS
}

pub fn otpauth_url(issuer: &str, account: &str, b32: &str) -> String {
    use url::form_urlencoded::byte_serialize;
    let enc = |s: &str| {
        byte_serialize(s.as_bytes())
            .collect::<String>()
            .replace('+', "%20")
    };
    let (i, a) = (enc(issuer), enc(account));
    format!("otpauth://totp/{i}:{a}?secret={b32}&issuer={i}&algorithm=SHA1&digits=6&period=30")
}

/// Render `data` as a compact terminal QR code (unicode half blocks).
/// Modules are drawn with the terminal foreground colour, so on a dark theme the
/// code is inverted: most authenticator apps scan that fine.
fn qr_ascii(data: &str) -> Option<String> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::new(data.as_bytes()).ok()?;
    Some(code.render::<Dense1x2>().quiet_zone(true).build())
}

pub fn gen_totp(issuer: &str, account: &str) -> ExitCode {
    let bytes: [u8; 20] = rand::random();
    let b32 = totp_rs::Secret::from(bytes).to_base32();
    let url = otpauth_url(issuer, account, &b32);
    println!("{b32}");
    println!("{url}");
    if let Some(qr) = qr_ascii(&url) {
        println!("\n{qr}");
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_ascii_renders() {
        let q = qr_ascii("otpauth://totp/a:b?secret=ABC").unwrap();
        assert!(q.lines().count() > 10 && q.contains('█') || q.contains('▀') || q.contains('▄'));
    }

    #[test]
    fn otpauth_url_encoding() {
        let u = otpauth_url("My App", "a@b.c", "ABC");
        assert_eq!(
            u,
            "otpauth://totp/My%20App:a%40b.c?secret=ABC&issuer=My%20App&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn hash_password_is_valid_argon2id() {
        let h = hash_password_str("correct horse").unwrap();
        assert!(crate::config::parse_gate::check_psk_hash(&h).is_ok());
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(hash_password_str("short").is_err() && hash_password_str("").is_err());
    }

    #[test]
    fn api_key_digest_matches_fixture() {
        assert_eq!(
            api_key_hex("test-api-key-0123456789"),
            "47bd0e2f856fe258ebba4d00930ab811d0c004dafae068c9d72511ca3512cca6"
        );
    }
}
