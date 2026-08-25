use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt as _;
use sha2::{Digest as _, Sha256};

use super::{
    OAuthClientSecretStorage, OAuthProviderConfig, OAuthStoredTokenType, OAuthTokenStorage,
};
use crate::{AuthError, AuthService};

const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALPHANUMERIC: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

pub(super) fn random_letters(length: usize) -> String {
    random_from(LETTERS, length)
}

pub(super) fn random_alphanumeric(length: usize) -> String {
    random_from(ALPHANUMERIC, length)
}

fn random_from(alphabet: &[u8], length: usize) -> String {
    let mut rng = rand::rng();
    (0..length)
        .map(|_| alphabet[rng.random_range(0..alphabet.len())] as char)
        .collect()
}

pub(super) fn hash_token(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

pub(super) fn client_assertion_id(namespace: &str, jti: &str) -> String {
    let digest = Sha256::digest(format!("{namespace}:{jti}").as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..24])
}

pub(super) fn verify_s256_pkce(verifier: &str, challenge: &str) -> bool {
    constant_time_equal(hash_token(verifier).as_bytes(), challenge.as_bytes())
}

pub(super) fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

pub(crate) async fn store_client_secret(
    service: &AuthService,
    config: &OAuthProviderConfig,
    plaintext: &str,
) -> Result<String, AuthError> {
    match effective_secret_storage(config) {
        OAuthClientSecretStorage::Automatic => unreachable!("automatic storage was resolved"),
        OAuthClientSecretStorage::Hashed => Ok(hash_token(plaintext)),
        OAuthClientSecretStorage::Encrypted => service
            .encrypt_oauth_provider_secret(plaintext.as_bytes())
            .map_err(|_| AuthError::Storage("OAuth client-secret encryption failed".into())),
        OAuthClientSecretStorage::CustomHashed(hasher) => hasher.hash(plaintext).await,
        OAuthClientSecretStorage::CustomEncrypted(cipher) => cipher.encrypt(plaintext).await,
    }
}

pub(crate) async fn verify_client_secret(
    service: &AuthService,
    config: &OAuthProviderConfig,
    plaintext: &str,
    stored: &str,
) -> Result<bool, AuthError> {
    match effective_secret_storage(config) {
        OAuthClientSecretStorage::Automatic => unreachable!("automatic storage was resolved"),
        OAuthClientSecretStorage::Hashed => Ok(constant_time_equal(
            hash_token(plaintext).as_bytes(),
            stored.as_bytes(),
        )),
        OAuthClientSecretStorage::Encrypted => {
            let Ok(decrypted) = service.decrypt_oauth_provider_secret(stored) else {
                return Ok(false);
            };
            Ok(constant_time_equal(plaintext.as_bytes(), &decrypted))
        }
        OAuthClientSecretStorage::CustomHashed(hasher) => hasher.verify(plaintext, stored).await,
        OAuthClientSecretStorage::CustomEncrypted(cipher) => {
            let decrypted = cipher.decrypt(stored).await?;
            Ok(constant_time_equal(
                plaintext.as_bytes(),
                decrypted.as_bytes(),
            ))
        }
    }
}

pub(crate) async fn decrypt_client_secret(
    service: &AuthService,
    config: &OAuthProviderConfig,
    stored: &str,
) -> Result<String, AuthError> {
    match effective_secret_storage(config) {
        OAuthClientSecretStorage::Encrypted => service
            .decrypt_oauth_provider_secret(stored)
            .map_err(|_| AuthError::Storage("OAuth client-secret decryption failed".into()))
            .and_then(|value| {
                String::from_utf8(value)
                    .map_err(|_| AuthError::Storage("OAuth client-secret decryption failed".into()))
            }),
        OAuthClientSecretStorage::CustomEncrypted(cipher) => cipher.decrypt(stored).await,
        _ => Err(AuthError::InvalidConfiguration(
            "hashed OAuth client secrets cannot sign HS256 ID tokens".into(),
        )),
    }
}

pub(crate) async fn store_token(
    config: &OAuthProviderConfig,
    token: &str,
    token_type: OAuthStoredTokenType,
) -> Result<String, AuthError> {
    match &config.store_tokens {
        OAuthTokenStorage::Hashed => Ok(hash_token(token)),
        OAuthTokenStorage::Custom(hasher) => hasher.hash(token, token_type).await,
    }
}

pub(crate) fn strip_token_prefix<'a>(
    config: &OAuthProviderConfig,
    token: &'a str,
    token_type: OAuthStoredTokenType,
) -> Option<&'a str> {
    let prefix = match token_type {
        OAuthStoredTokenType::AccessToken => config.prefix.opaque_access_token.as_deref(),
        OAuthStoredTokenType::RefreshToken => config.prefix.refresh_token.as_deref(),
        OAuthStoredTokenType::AuthorizationCode => None,
    };
    match prefix {
        Some(prefix) => token.strip_prefix(prefix),
        None => Some(token),
    }
}

pub(crate) fn apply_token_prefix(
    config: &OAuthProviderConfig,
    token: String,
    token_type: OAuthStoredTokenType,
) -> String {
    let prefix = match token_type {
        OAuthStoredTokenType::AccessToken => config.prefix.opaque_access_token.as_deref(),
        OAuthStoredTokenType::RefreshToken => config.prefix.refresh_token.as_deref(),
        OAuthStoredTokenType::AuthorizationCode => None,
    };
    match prefix {
        Some(prefix) => format!("{prefix}{token}"),
        None => token,
    }
}

fn effective_secret_storage(config: &OAuthProviderConfig) -> OAuthClientSecretStorage {
    match &config.store_client_secret {
        OAuthClientSecretStorage::Automatic if config.disable_jwt_plugin => {
            OAuthClientSecretStorage::Encrypted
        }
        OAuthClientSecretStorage::Automatic => OAuthClientSecretStorage::Hashed,
        configured => configured.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identifiers_use_the_upstream_alphabet() {
        let value = random_letters(32);
        assert_eq!(value.len(), 32);
        assert!(value.bytes().all(|byte| byte.is_ascii_alphabetic()));
    }

    #[test]
    fn hashes_and_pkce_match_sha256_base64url() {
        assert_eq!(
            hash_token("secret"),
            "K7gNU3sdo-OL0wNhqoVWhr3g6s1xYv72ol_pe_Unols"
        );
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(verify_s256_pkce(
            verifier,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!verify_s256_pkce(verifier, "wrong"));
    }
}
