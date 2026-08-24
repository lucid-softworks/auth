#[cfg(test)]
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::{Map, Value};
use std::sync::Arc;
use thiserror::Error;

mod jwks;

#[cfg(test)]
use jwks::StaticGoogleJwksSource;
use jwks::{GoogleJwksHttpSource, GoogleJwksSource};

const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];
const MAX_TOKEN_AGE_SECONDS: i64 = 60 * 60;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct GoogleIdTokenClaims {
    pub(crate) subject: String,
    pub(crate) issuer: String,
    pub(crate) email: String,
    pub(crate) email_verified: bool,
    pub(crate) name: String,
    pub(crate) picture: Option<String>,
    pub(crate) hosted_domain: Option<String>,
    pub(crate) profile: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum GoogleIdTokenError {
    #[error("Google client ID is required")]
    MissingAudience,
    #[error("Google ID token must use RS256")]
    UnsupportedAlgorithm,
    #[error("Google signing keys are unavailable")]
    JwksUnavailable,
    #[error("Google signing key was not found")]
    KeyNotFound,
    #[error("Google ID token is invalid")]
    InvalidToken,
    #[error("Google ID token has expired")]
    Expired,
    #[error("Google ID token was issued more than one hour ago")]
    TooOld,
    #[error("Google ID token was issued in the future")]
    IssuedInFuture,
    #[error("Google ID token subject is missing")]
    MissingSubject,
    #[error("Google ID token email is missing")]
    MissingEmail,
    #[error("Google ID token hosted domain is not allowed")]
    HostedDomainMismatch,
}

#[derive(Clone)]
pub(crate) struct GoogleIdTokenVerifier {
    jwks: Arc<dyn GoogleJwksSource>,
}

impl GoogleIdTokenVerifier {
    pub(crate) fn production() -> Self {
        Self::with_jwks_url(GOOGLE_JWKS_URL)
    }

    pub(crate) fn with_jwks_url(jwks_url: impl Into<String>) -> Self {
        Self {
            jwks: Arc::new(GoogleJwksHttpSource::new(jwks_url)),
        }
    }

    pub(crate) async fn verify(
        &self,
        token: &str,
        audiences: &[String],
        hosted_domain: Option<&str>,
    ) -> Result<GoogleIdTokenClaims, GoogleIdTokenError> {
        self.verify_at(
            token,
            audiences,
            hosted_domain,
            chrono::Utc::now().timestamp(),
        )
        .await
    }

    async fn verify_at(
        &self,
        token: &str,
        audiences: &[String],
        hosted_domain: Option<&str>,
        now: i64,
    ) -> Result<GoogleIdTokenClaims, GoogleIdTokenError> {
        if audiences.is_empty() {
            return Err(GoogleIdTokenError::MissingAudience);
        }
        let header = decode_header(token).map_err(|_| GoogleIdTokenError::InvalidToken)?;
        if header.alg != Algorithm::RS256 {
            return Err(GoogleIdTokenError::UnsupportedAlgorithm);
        }
        let jwks = self.jwks.fetch().await?;
        let matching = jwks.keys.iter().filter(|key| {
            header
                .kid
                .as_deref()
                .filter(|kid| !kid.is_empty())
                .is_none_or(|kid| key.common.key_id.as_deref() == Some(kid))
        });
        let mut found = false;
        for jwk in matching {
            found = true;
            let Ok(key) = DecodingKey::from_jwk(jwk) else {
                continue;
            };
            if let Ok(data) = decode::<Value>(token, &key, &validation(audiences)) {
                return map_claims(data.claims, hosted_domain, now);
            }
        }
        Err(if found {
            GoogleIdTokenError::InvalidToken
        } else {
            GoogleIdTokenError::KeyNotFound
        })
    }

    #[cfg(test)]
    fn from_jwks(jwks: JwkSet) -> Self {
        Self {
            jwks: Arc::new(StaticGoogleJwksSource(jwks)),
        }
    }
}

fn validation(audiences: &[String]) -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(audiences);
    validation.set_issuer(&GOOGLE_ISSUERS);
    validation.set_required_spec_claims(&["iss", "aud", "sub"]);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.leeway = 0;
    validation
}

fn map_claims(
    claims: Value,
    configured_hosted_domain: Option<&str>,
    now: i64,
) -> Result<GoogleIdTokenClaims, GoogleIdTokenError> {
    let profile = claims
        .as_object()
        .cloned()
        .ok_or(GoogleIdTokenError::InvalidToken)?;
    if let Some(expiration) = profile.get("exp") {
        let expiration = numeric_date(expiration)?;
        if expiration <= now as f64 {
            return Err(GoogleIdTokenError::Expired);
        }
    }
    if let Some(not_before) = profile.get("nbf")
        && numeric_date(not_before)? > now as f64
    {
        return Err(GoogleIdTokenError::InvalidToken);
    }
    let issued_at = profile.get("iat").ok_or(GoogleIdTokenError::InvalidToken)?;
    let issued_at = numeric_date(issued_at)?;
    if issued_at > now as f64 {
        return Err(GoogleIdTokenError::IssuedInFuture);
    }
    if now as f64 - issued_at > MAX_TOKEN_AGE_SECONDS as f64 {
        return Err(GoogleIdTokenError::TooOld);
    }
    let subject = required_nonempty_string(&profile, "sub", GoogleIdTokenError::MissingSubject)?;
    let email = required_nonempty_string(&profile, "email", GoogleIdTokenError::MissingEmail)?
        .to_lowercase();
    let issuer = profile
        .get("iss")
        .and_then(Value::as_str)
        .ok_or(GoogleIdTokenError::InvalidToken)?
        .to_owned();
    let hosted_domain = optional_string(&profile, "hd");
    if !hosted_domain_is_allowed(configured_hosted_domain, hosted_domain.as_deref()) {
        return Err(GoogleIdTokenError::HostedDomainMismatch);
    }
    Ok(GoogleIdTokenClaims {
        subject,
        issuer,
        email,
        email_verified: matches!(profile.get("email_verified"), Some(Value::Bool(true)))
            || profile.get("email_verified").and_then(Value::as_str) == Some("true"),
        name: optional_string(&profile, "name").unwrap_or_default(),
        picture: optional_string(&profile, "picture"),
        hosted_domain,
        profile,
    })
}

fn numeric_date(value: &Value) -> Result<f64, GoogleIdTokenError> {
    value
        .as_f64()
        .filter(|value| value.is_finite())
        .ok_or(GoogleIdTokenError::InvalidToken)
}

fn required_nonempty_string(
    claims: &Map<String, Value>,
    name: &str,
    error: GoogleIdTokenError,
) -> Result<String, GoogleIdTokenError> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(error)
}

fn optional_string(claims: &Map<String, Value>, name: &str) -> Option<String> {
    claims.get(name).and_then(Value::as_str).map(str::to_owned)
}

pub(crate) fn hosted_domain_is_allowed(configured: Option<&str>, token: Option<&str>) -> bool {
    match configured.filter(|domain| !domain.is_empty()) {
        None => true,
        Some("*") => token.is_some_and(|domain| !domain.is_empty()),
        Some(expected) => token == Some(expected),
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use jsonwebtoken::{EncodingKey, Header, encode, jwk::AlgorithmParameters};
    use serde_json::{Value, json};

    pub(crate) const AUDIENCE: &str = "web-client";
    const PRIVATE_KEY: &str = include_str!("testdata/google_rsa_private_key.der.b64");

    fn signing_key() -> EncodingKey {
        let encoded = PRIVATE_KEY.lines().collect::<String>();
        EncodingKey::from_rsa_der(&STANDARD.decode(encoded).unwrap())
    }

    pub(super) fn jwk(kid: &str, valid: bool) -> jsonwebtoken::jwk::Jwk {
        let mut key =
            jsonwebtoken::jwk::Jwk::from_encoding_key(&signing_key(), Algorithm::RS256).unwrap();
        key.common.key_id = Some(kid.into());
        if !valid && let AlgorithmParameters::RSA(parameters) = &mut key.algorithm {
            parameters.n.replace_range(..1, "A");
        }
        key
    }

    pub(super) fn token_at(kid: Option<&str>, overrides: Value, now: i64) -> String {
        let mut claims = json!({
            "iss": GOOGLE_ISSUERS[0], "aud": AUDIENCE, "sub": "subject-1",
            "email": "Casey@EXAMPLE.com", "email_verified": true,
            "iat": now, "exp": now + 3600, "nonce": "ignored-by-one-tap"
        });
        claims
            .as_object_mut()
            .unwrap()
            .extend(overrides.as_object().cloned().unwrap_or_default());
        let mut header = Header::new(Algorithm::RS256);
        header.kid = kid.map(str::to_owned);
        encode(&header, &claims, &signing_key()).unwrap()
    }

    pub(super) fn verifier(keys: Vec<jsonwebtoken::jwk::Jwk>) -> GoogleIdTokenVerifier {
        GoogleIdTokenVerifier::from_jwks(JwkSet { keys })
    }

    pub(crate) fn verifier_and_token(overrides: Value) -> (GoogleIdTokenVerifier, String) {
        let now = chrono::Utc::now().timestamp();
        (
            verifier(vec![jwk("current", true)]),
            token_at(Some("current"), overrides, now),
        )
    }
}

#[cfg(test)]
#[path = "google_id_token/verification_tests.rs"]
mod tests;
