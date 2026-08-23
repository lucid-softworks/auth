use crate::AuthError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "axum")]
use chacha20poly1305::aead::{OsRng, rand_core::RngCore};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
#[cfg(feature = "axum")]
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
#[cfg(feature = "axum")]
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use sha1::Sha1;
use sha2::{Digest, Sha256};

const ENVELOPE_PREFIX: &str = "$la$1$";
#[cfg(feature = "axum")]
const ENCODE_URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

#[cfg(feature = "axum")]
pub(crate) fn encrypt(secret: &[u8], plaintext: &[u8]) -> Result<String, AuthError> {
    let key = Sha256::digest(secret);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| AuthError::InvalidConfiguration("two-factor key is invalid".into()))?;
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| AuthError::Storage("two-factor encryption failed".into()))?;
    let mut envelope = Vec::with_capacity(nonce.len() + ciphertext.len());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(format!(
        "{ENVELOPE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(envelope)
    ))
}

pub(crate) fn decrypt(secret: &[u8], encrypted: &str) -> Result<Vec<u8>, AuthError> {
    let encoded = encrypted
        .strip_prefix(ENVELOPE_PREFIX)
        .ok_or_else(|| AuthError::Storage("two-factor ciphertext is invalid".into()))?;
    let envelope = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| AuthError::Storage("two-factor ciphertext is invalid".into()))?;
    let (nonce, ciphertext) = envelope
        .split_at_checked(24)
        .ok_or_else(|| AuthError::Storage("two-factor ciphertext is invalid".into()))?;
    let key = Sha256::digest(secret);
    XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| AuthError::InvalidConfiguration("two-factor key is invalid".into()))?
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| AuthError::Storage("two-factor decryption failed".into()))
}

#[cfg(feature = "axum")]
pub(crate) fn totp_uri(
    secret: &str,
    issuer: &str,
    account: &str,
    digits: u32,
    period_seconds: i64,
) -> String {
    let path_issuer = utf8_percent_encode(issuer, ENCODE_URI_COMPONENT);
    let path_account = utf8_percent_encode(account, ENCODE_URI_COMPONENT);
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("secret", &BASE32_NOPAD.encode(secret.as_bytes()))
        .append_pair("issuer", issuer)
        .append_pair("digits", &digits.to_string())
        .append_pair("period", &period_seconds.to_string())
        .finish();
    format!("otpauth://totp/{path_issuer}:{path_account}?{query}")
}

#[cfg(feature = "axum")]
pub(crate) fn verify_totp(
    secret: &str,
    code: &str,
    digits: u32,
    period_seconds: i64,
    timestamp: i64,
) -> Option<i64> {
    if code.len() != digits as usize || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let counter = timestamp.div_euclid(period_seconds);
    (-1..=1)
        .map(|offset| counter + offset)
        .find(|candidate| hotp(secret.as_bytes(), *candidate as u64, digits) == code)
}

pub(crate) fn current_totp(
    secret: &str,
    digits: u32,
    period_seconds: i64,
    timestamp: i64,
) -> String {
    hotp(
        secret.as_bytes(),
        timestamp.div_euclid(period_seconds) as u64,
        digits,
    )
}

fn hotp(secret: &[u8], counter: u64, digits: u32) -> String {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC accepts any key");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = usize::from(result[result.len() - 1] & 0x0f);
    let value = (u32::from(result[offset] & 0x7f) << 24)
        | (u32::from(result[offset + 1]) << 16)
        | (u32::from(result[offset + 2]) << 8)
        | u32::from(result[offset + 3]);
    let modulus = 10_u32.pow(digits);
    format!("{:0width$}", value % modulus, width = digits as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "axum")]
    #[test]
    fn encrypts_and_authenticates_secrets() {
        let encrypted = encrypt(&[9; 32], b"secret").unwrap();
        assert_ne!(encrypted, "secret");
        assert_eq!(decrypt(&[9; 32], &encrypted).unwrap(), b"secret");
        assert!(decrypt(&[8; 32], &encrypted).is_err());
    }

    #[test]
    fn totp_matches_rfc_6238_sha1_vector() {
        assert_eq!(current_totp("12345678901234567890", 8, 30, 59), "94287082");
    }

    #[cfg(feature = "axum")]
    #[test]
    fn totp_uri_matches_better_auths_encode_uri_component_profile() {
        assert_eq!(
            totp_uri("abc", "lucid-auth conformance", "a+b@example.com", 6, 30),
            "otpauth://totp/lucid-auth%20conformance:a%2Bb%40example.com?secret=MFRGG&issuer=lucid-auth+conformance&digits=6&period=30"
        );
    }
}
