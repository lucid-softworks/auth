use crate::AuthError;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone)]
pub(super) struct EmailVerificationClaims {
    pub(super) email: String,
    pub(super) update_to: Option<String>,
    pub(super) request_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IssuedEmailVerificationClaims {
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    update_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_type: Option<String>,
    iat: i64,
    exp: i64,
}

pub(super) fn encode_email_verification_token(
    secret: &[u8],
    email: &str,
    update_to: Option<&str>,
    request_type: Option<&str>,
    now: DateTime<Utc>,
    expires_in: Duration,
) -> Result<String, AuthError> {
    let issued_at = now.timestamp();
    let claims = IssuedEmailVerificationClaims {
        email: email.to_lowercase(),
        update_to: update_to.map(str::to_lowercase),
        request_type: request_type.map(str::to_owned),
        iat: issued_at,
        exp: issued_at + expires_in.num_seconds(),
    };
    let mut header = Header::new(Algorithm::HS256);
    header.typ = None;
    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(secret))
        .map_err(|_| AuthError::Worker)
}

pub(super) fn decode_email_verification_token(
    secret: &[u8],
    token: &str,
    now: DateTime<Utc>,
) -> Result<EmailVerificationClaims, AuthError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.leeway = 0;
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    let payload =
        jsonwebtoken::decode::<Value>(token, &DecodingKey::from_secret(secret), &validation)
            .map(|decoded| decoded.claims)
            .map_err(|_| AuthError::InvalidToken)?;
    if validate_numeric_date(&payload, "nbf", |value| (now.timestamp() as f64) < value)? {
        return Err(AuthError::InvalidToken);
    }
    if validate_numeric_date(&payload, "exp", |value| (now.timestamp() as f64) >= value)? {
        return Err(AuthError::TokenExpired);
    }
    let email = string_claim(&payload, "email", true)?.ok_or(AuthError::InvalidToken)?;
    if !crate::service::email_password::valid_email(&email) {
        return Err(AuthError::InvalidToken);
    }
    Ok(EmailVerificationClaims {
        email,
        update_to: string_claim(&payload, "updateTo", false)?,
        request_type: string_claim(&payload, "requestType", false)?,
    })
}

fn validate_numeric_date(
    payload: &Value,
    claim: &str,
    invalid: impl FnOnce(f64) -> bool,
) -> Result<bool, AuthError> {
    let Some(value) = payload.get(claim) else {
        return Ok(false);
    };
    let value = value.as_f64().ok_or(AuthError::InvalidToken)?;
    Ok(invalid(value))
}

fn string_claim(payload: &Value, claim: &str, required: bool) -> Result<Option<String>, AuthError> {
    match payload.get(claim) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        None if !required => Ok(None),
        _ => Err(AuthError::InvalidToken),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::TimeZone;
    use serde_json::json;

    const SECRET: &[u8] = b"email-token-test-secret-at-least-32-bytes";

    #[test]
    fn issued_tokens_have_the_exact_header_and_temporal_claims() {
        let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let token = encode_email_verification_token(
            SECRET,
            "Current@Example.com",
            Some("New@Example.com"),
            Some("change-email-confirmation"),
            now,
            Duration::minutes(30),
        )
        .unwrap();
        let segments = token.split('.').collect::<Vec<_>>();
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0]).unwrap()).unwrap();
        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();

        assert_eq!(header, json!({ "alg": "HS256" }));
        assert_eq!(
            payload,
            json!({
                "email": "current@example.com",
                "updateTo": "new@example.com",
                "requestType": "change-email-confirmation",
                "iat": 1_700_000_000_i64,
                "exp": 1_700_001_800_i64
            })
        );
        assert!(decode_email_verification_token(SECRET, &token, now).is_ok());
    }

    #[test]
    fn verifier_has_no_leeway_and_does_not_require_temporal_claims() {
        let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let without_dates = signed(json!({ "email": "valid@example.com" }), Algorithm::HS256);
        assert!(decode_email_verification_token(SECRET, &without_dates, now).is_ok());

        let expired = signed(
            json!({ "email": "valid@example.com", "exp": now.timestamp() }),
            Algorithm::HS256,
        );
        assert!(matches!(
            decode_email_verification_token(SECRET, &expired, now),
            Err(AuthError::TokenExpired)
        ));
    }

    #[test]
    fn verifier_rejects_signature_algorithm_and_payload_failures() {
        let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let wrong_secret = {
            let mut header = Header::new(Algorithm::HS256);
            header.typ = None;
            jsonwebtoken::encode(
                &header,
                &json!({ "email": "valid@example.com" }),
                &EncodingKey::from_secret(b"a different secret with enough entropy"),
            )
            .unwrap()
        };
        for token in [
            "not-a-jwt".to_owned(),
            wrong_secret,
            signed(json!({ "email": "valid@example.com" }), Algorithm::HS384),
            signed(json!({}), Algorithm::HS256),
            signed(json!({ "email": "invalid" }), Algorithm::HS256),
            signed(
                json!({ "email": "valid@example.com", "requestType": null }),
                Algorithm::HS256,
            ),
        ] {
            assert!(matches!(
                decode_email_verification_token(SECRET, &token, now),
                Err(AuthError::InvalidToken)
            ));
        }
    }

    fn signed(payload: Value, algorithm: Algorithm) -> String {
        let mut header = Header::new(algorithm);
        header.typ = None;
        jsonwebtoken::encode(&header, &payload, &EncodingKey::from_secret(SECRET)).unwrap()
    }
}
