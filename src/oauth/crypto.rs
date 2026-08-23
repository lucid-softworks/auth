use crate::AuthError;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use sha2::{Digest, Sha256};

const PREFIX: &str = "$la$oauth$1$";
const AAD: &[u8] = b"lucid-auth:oauth-token:v1";

pub(crate) fn encrypt(secret: &[u8], value: Option<String>) -> Result<Option<String>, AuthError> {
    value.map(|value| encrypt_value(secret, &value)).transpose()
}

fn encrypt_value(secret: &[u8], value: &str) -> Result<String, AuthError> {
    let key = Sha256::digest([b"lucid-auth:oauth-key:v1".as_slice(), secret].concat());
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| AuthError::Worker)?;
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: value.as_bytes(),
                aad: AAD,
            },
        )
        .map_err(|_| AuthError::Worker)?;
    Ok(format!(
        "{PREFIX}{}.{}",
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(ciphertext)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_tokens_are_randomized_envelopes() {
        let secret = [7_u8; 32];
        let first = encrypt_value(&secret, "provider-secret").unwrap();
        let second = encrypt_value(&secret, "provider-secret").unwrap();
        assert_ne!(first, second);
        assert!(!first.contains("provider-secret"));
        assert!(first.starts_with(PREFIX));
    }
}
