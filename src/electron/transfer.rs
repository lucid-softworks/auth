use super::ElectronOptions;
use crate::{AuthError, AuthService, VerificationValue};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use rand::RngExt as _;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

const IDENTIFIER_ALPHABET: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IssuedTransfer {
    pub identifier: String,
    pub redirect_token: String,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum ExchangeError {
    #[error("Invalid or expired token.")]
    InvalidToken,
    #[error("Invalid or expired token.")]
    MalformedToken,
    #[error("state mismatch")]
    StateMismatch,
    #[error("missing code challenge")]
    MissingCodeChallenge,
    #[error("Invalid code verifier")]
    InvalidCodeVerifier,
    #[error("User not found")]
    UserNotFound,
    #[error("Failed to create session")]
    FailedToCreateSession,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredTransfer<'a> {
    user_id: &'a str,
    code_challenge: &'a str,
    state: &'a str,
}

#[derive(Serialize)]
struct RedirectToken<'a> {
    identifier: &'a str,
    state: &'a str,
}

pub(super) async fn issue(
    service: &AuthService,
    options: &ElectronOptions,
    user_id: &str,
    state: &str,
    code_challenge: &str,
) -> Result<IssuedTransfer, AuthError> {
    let identifier = random_identifier();
    let payload = serde_json::to_string(&StoredTransfer {
        user_id,
        code_challenge,
        state,
    })
    .map_err(|_| AuthError::Worker)?;
    service
        .create_verification_value(VerificationValue::new(
            format!("electron:{identifier}"),
            payload,
            Utc::now() + Duration::seconds(options.code_expires_in),
        ))
        .await?;
    let redirect = serde_json::to_vec(&RedirectToken {
        identifier: &identifier,
        state,
    })
    .map_err(|_| AuthError::Worker)?;
    Ok(IssuedTransfer {
        identifier,
        redirect_token: URL_SAFE_NO_PAD.encode(redirect),
    })
}

#[cfg(feature = "axum")]
pub(super) async fn exchange(
    service: &AuthService,
    identifier: &str,
    state: &str,
    code_verifier: &str,
) -> Result<crate::SignInResult, ExchangeError> {
    let record = service
        .consume_verification_value(&format!("electron:{identifier}"), Utc::now())
        .await
        .map_err(|_| ExchangeError::MalformedToken)?
        .ok_or(ExchangeError::InvalidToken)?;
    let payload: serde_json::Value =
        serde_json::from_str(&record.value).map_err(|_| ExchangeError::MalformedToken)?;
    if javascript_falsey(&payload) {
        return Err(ExchangeError::MalformedToken);
    }
    if payload.get("state").and_then(serde_json::Value::as_str) != Some(state) {
        return Err(ExchangeError::StateMismatch);
    }
    let Some(challenge) = payload
        .get("codeChallenge")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return Err(ExchangeError::MissingCodeChallenge);
    };
    if code_challenge(code_verifier) != challenge {
        return Err(ExchangeError::InvalidCodeVerifier);
    }
    let user_id = payload
        .get("userId")
        .and_then(serde_json::Value::as_str)
        .ok_or(ExchangeError::UserNotFound)?;
    service
        .create_electron_session(user_id)
        .await
        .map_err(|_| ExchangeError::FailedToCreateSession)?
        .ok_or(ExchangeError::UserNotFound)
}

pub(super) fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn random_identifier() -> String {
    let mut rng = rand::rng();
    (0..32)
        .map(|_| IDENTIFIER_ALPHABET[rng.random_range(0..IDENTIFIER_ALPHABET.len())] as char)
        .collect()
}

fn javascript_falsey(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => true,
        serde_json::Value::Bool(value) => !value,
        serde_json::Value::Number(value) => value.as_f64() == Some(0.0),
        serde_json::Value::String(value) => value.is_empty(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_token_is_exact_base64url_json_and_the_code_is_raw() {
        let redirect = serde_json::to_vec(&RedirectToken {
            identifier: "0123456789abcdefghijklmnopqrstuv",
            state: "state",
        })
        .unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(redirect);
        assert_eq!(
            String::from_utf8(URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap(),
            r#"{"identifier":"0123456789abcdefghijklmnopqrstuv","state":"state"}"#
        );
    }

    #[test]
    fn pkce_is_always_s256() {
        assert_eq!(
            code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
