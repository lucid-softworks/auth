use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use sha2::{Digest, Sha256};

pub(crate) fn encrypt(secret: &[u8], plaintext: &[u8]) -> Result<String, ()> {
    let key = Sha256::digest(secret);
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| ())?;
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| ())?;
    let mut envelope = Vec::with_capacity(nonce.len() + ciphertext.len());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(hex::encode(envelope))
}

pub(crate) fn decrypt(secret: &[u8], envelope: &str) -> Result<Vec<u8>, ()> {
    let envelope = hex::decode(envelope).map_err(|_| ())?;
    if envelope.len() < 40 {
        return Err(());
    }
    let (nonce, ciphertext) = envelope.split_at(24);
    let key = Sha256::digest(secret);
    XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| ())?
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn better_auth_envelope_is_randomized_nonce_prefixed_hex() {
        let secret = b"better-auth-compatible-secret";
        let first = encrypt(secret, b"provider-secret").unwrap();
        let second = encrypt(secret, b"provider-secret").unwrap();
        assert_ne!(first, second);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(decrypt(secret, &first).unwrap(), b"provider-secret");
        assert!(decrypt(b"different-secret", &first).is_err());
    }

    #[test]
    fn decrypts_a_better_auth_1_7_1_symmetric_encrypt_fixture() {
        let fixture = "c34230fefe1b18b3e6773214ebd090223830e5bd23f3eebe5934d3184d13d791a6bb658eb4a900d82cfd4dbc9ecb86e9c9ea92";
        assert_eq!(
            decrypt(b"compatible-secret", fixture).unwrap(),
            b"oauth-state"
        );
    }
}
