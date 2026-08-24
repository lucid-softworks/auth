use crate::AuthError;
use aes::Aes256;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngExt;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

type HmacSha512 = Hmac<Sha512>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

const JWE_INFO: &[u8] = b"BetterAuth.js Generated Encryption Key";

#[derive(serde::Serialize, serde::Deserialize)]
struct JweHeader {
    alg: String,
    enc: String,
    kid: String,
}

pub(crate) fn encode<T: Serialize>(
    payload: T,
    secret: &[u8],
    salt: &[u8],
    max_age_seconds: i64,
) -> Result<String, AuthError> {
    let key = derive_key(secret, salt)?;
    let header = JweHeader {
        alg: "dir".into(),
        enc: "A256CBC-HS512".into(),
        kid: jwk_thumbprint(&key),
    };
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(json_error)?);
    let iv: [u8; 16] = rand::rng().random();
    let now = chrono::Utc::now().timestamp();
    let mut payload = serde_json::to_value(payload).map_err(json_error)?;
    let object = payload.as_object_mut().ok_or_else(|| {
        AuthError::InvalidConfiguration("symmetric JWE payload must be an object".into())
    })?;
    object.insert("iat".into(), Value::from(now));
    object.insert("exp".into(), Value::from(now + max_age_seconds));
    object.insert("jti".into(), Value::from(uuid::Uuid::new_v4().to_string()));
    let plaintext = serde_json::to_vec(&payload).map_err(json_error)?;
    let ciphertext = Aes256CbcEnc::new_from_slices(&key[32..], &iv)
        .map_err(|_| crypto_error("invalid JWE encryption key"))?
        .encrypt_padded_vec_mut::<Pkcs7>(&plaintext);
    let tag = authentication_tag(&key[..32], protected.as_bytes(), &iv, &ciphertext)?;
    Ok(format!(
        "{protected}..{}.{}.{}",
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(ciphertext),
        URL_SAFE_NO_PAD.encode(tag)
    ))
}

pub(crate) fn decode<T: DeserializeOwned>(
    value: &str,
    secret: &[u8],
    salt: &[u8],
) -> Option<(T, i64)> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 5 || !parts[1].is_empty() {
        return None;
    }
    let header: JweHeader = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).ok()?).ok()?;
    if header.alg != "dir" || header.enc != "A256CBC-HS512" {
        return None;
    }
    let key = derive_key(secret, salt).ok()?;
    if header.kid != jwk_thumbprint(&key) {
        return None;
    }
    let iv = URL_SAFE_NO_PAD.decode(parts[2]).ok()?;
    let ciphertext = URL_SAFE_NO_PAD.decode(parts[3]).ok()?;
    let supplied_tag = URL_SAFE_NO_PAD.decode(parts[4]).ok()?;
    let expected_tag =
        authentication_tag(&key[..32], parts[0].as_bytes(), &iv, &ciphertext).ok()?;
    if !constant_time_equal(&supplied_tag, &expected_tag) {
        return None;
    }
    let plaintext = Aes256CbcDec::new_from_slices(&key[32..], &iv)
        .ok()?
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
        .ok()?;
    let mut payload: Value = serde_json::from_slice(&plaintext).ok()?;
    let expires_at = payload.get("exp")?.as_i64()?;
    (expires_at.saturating_add(15) > chrono::Utc::now().timestamp()).then(|| {
        if let Some(object) = payload.as_object_mut() {
            object.remove("iat");
            object.remove("exp");
            object.remove("jti");
        }
        serde_json::from_value(payload)
            .ok()
            .map(|payload| (payload, expires_at.saturating_mul(1_000)))
    })?
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

fn derive_key(secret: &[u8], salt: &[u8]) -> Result<[u8; 64], AuthError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut key = [0_u8; 64];
    hkdf.expand(JWE_INFO, &mut key)
        .map_err(|_| crypto_error("could not derive JWE key"))?;
    Ok(key)
}

fn jwk_thumbprint(key: &[u8]) -> String {
    let canonical = format!(
        "{{\"k\":\"{}\",\"kty\":\"oct\"}}",
        URL_SAFE_NO_PAD.encode(key)
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn authentication_tag(
    mac_key: &[u8],
    aad: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AuthError> {
    let mut mac = HmacSha512::new_from_slice(mac_key)
        .map_err(|_| crypto_error("invalid JWE authentication key"))?;
    mac.update(aad);
    mac.update(iv);
    mac.update(ciphertext);
    mac.update(&(u64::try_from(aad.len()).unwrap_or(u64::MAX) * 8).to_be_bytes());
    Ok(mac.finalize().into_bytes()[..32].to_vec())
}

fn json_error(error: serde_json::Error) -> AuthError {
    AuthError::Storage(format!("symmetric JWE JSON failed: {error}"))
}

fn crypto_error(message: &str) -> AuthError {
    AuthError::InvalidConfiguration(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_jwe_rejects_tampering_and_expiry_beyond_better_auth_tolerance() {
        let secret = [82; 32];
        let value = encode(
            serde_json::json!({ "accountId": "provider-subject" }),
            &secret,
            b"better-auth-account",
            300,
        )
        .unwrap();
        let (payload, _) = decode::<Value>(&value, &secret, b"better-auth-account").unwrap();
        assert_eq!(payload["accountId"], "provider-subject");
        assert!(payload.get("iat").is_none());
        assert!(payload.get("exp").is_none());
        assert!(payload.get("jti").is_none());

        let mut tampered = value.into_bytes();
        let last = tampered.last_mut().unwrap();
        *last = if *last == b'A' { b'B' } else { b'A' };
        assert!(
            decode::<Value>(
                std::str::from_utf8(&tampered).unwrap(),
                &secret,
                b"better-auth-account"
            )
            .is_none()
        );

        let expired = encode(
            serde_json::json!({ "accountId": "provider-subject" }),
            &secret,
            b"better-auth-account",
            -16,
        )
        .unwrap();
        assert!(decode::<Value>(&expired, &secret, b"better-auth-account").is_none());
    }
}
