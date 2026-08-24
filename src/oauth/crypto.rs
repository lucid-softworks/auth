use crate::AuthError;

pub(crate) fn encrypt(secret: &[u8], value: Option<String>) -> Result<Option<String>, AuthError> {
    value.map(|value| encrypt_value(secret, &value)).transpose()
}

pub(crate) fn decrypt(secret: &[u8], value: Option<&str>) -> Result<Option<String>, AuthError> {
    value.map(|value| decrypt_value(secret, value)).transpose()
}

fn decrypt_value(secret: &[u8], value: &str) -> Result<String, AuthError> {
    let plaintext = crate::symmetric_crypto::decrypt(secret, value)
        .map_err(|_| AuthError::OAuthInvalidToken)?;
    String::from_utf8(plaintext).map_err(|_| AuthError::OAuthInvalidToken)
}

fn encrypt_value(secret: &[u8], value: &str) -> Result<String, AuthError> {
    crate::symmetric_crypto::encrypt(secret, value.as_bytes()).map_err(|_| AuthError::Worker)
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
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(decrypt_value(&secret, &first).unwrap(), "provider-secret");
        assert!(decrypt_value(&[8_u8; 32], &first).is_err());
    }
}
