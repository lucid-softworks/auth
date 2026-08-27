use super::{DashApiClient, DashRequest, ResolvedConnectionOptions};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::{fmt, sync::Arc, time::SystemTime};

mod cache;
mod signature;

const MAX_TOKEN_AGE_SECONDS: f64 = 300.0;
const JTI_GRACE_PERIOD_SECONDS: f64 = 30.0;

/// The exact hosted-route authorization failure exposed by Infra.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Invalid API key")]
pub struct DashAuthorizationError;

/// Claims returned by the hosted JWT middleware after optional route parsing.
#[derive(Clone, Debug, PartialEq)]
pub struct DashVerifiedClaims(pub Value);

/// Hosted JWT/JWKS/JTI verifier shared by Dash endpoint families.
#[derive(Clone)]
pub struct DashJwtVerifier {
    api: DashApiClient,
    api_url: Arc<str>,
    api_key: Arc<str>,
    now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
}

impl DashJwtVerifier {
    pub fn new(options: &ResolvedConnectionOptions) -> Self {
        Self {
            api: DashApiClient::new(options),
            api_url: Arc::from(options.api_url.as_str()),
            api_key: Arc::from(options.api_key()),
            now: Arc::new(SystemTime::now),
        }
    }

    #[cfg(all(test, feature = "axum"))]
    fn with_clock(
        options: &ResolvedConnectionOptions,
        now: impl Fn() -> SystemTime + Send + Sync + 'static,
    ) -> Self {
        let mut verifier = Self::new(options);
        verifier.now = Arc::new(now);
        verifier
    }

    /// Apply the regular hosted-route policy, including the conditional JTI call.
    pub async fn verify_authorization(
        &self,
        authorization: Option<&str>,
    ) -> Result<DashVerifiedClaims, DashAuthorizationError> {
        self.verify_authorization_with(authorization, |claims| Some(Value::Object(claims.clone())))
            .await
    }

    /// Apply the regular hosted-route policy and an exact route-claim parser.
    pub async fn verify_authorization_with(
        &self,
        authorization: Option<&str>,
        parse: impl FnOnce(&Map<String, Value>) -> Option<Value>,
    ) -> Result<DashVerifiedClaims, DashAuthorizationError> {
        let token = authorization
            .and_then(|value| value.split(' ').nth(1))
            .filter(|value| !value.is_empty())
            .ok_or(DashAuthorizationError)?;
        self.verify_token_with(token, true, parse).await
    }

    /// Apply `/dash/validate` policy: signature, token age, and API-key hash only.
    pub async fn validate_authorization(
        &self,
        authorization: Option<&str>,
    ) -> Result<DashVerifiedClaims, DashAuthorizationError> {
        let token = authorization
            .and_then(|value| value.split(' ').nth(1))
            .filter(|value| !value.is_empty())
            .ok_or(DashAuthorizationError)?;
        self.verify_token_with(token, false, |claims| Some(Value::Object(claims.clone())))
            .await
    }

    /// Apply the hosted-route policy to a token supplied by an endpoint getter.
    pub async fn verify_token_with(
        &self,
        token: &str,
        check_jti: bool,
        parse: impl FnOnce(&Map<String, Value>) -> Option<Value>,
    ) -> Result<DashVerifiedClaims, DashAuthorizationError> {
        let jwks = cache::get(&self.api_url, &self.api).await?;
        let claims = signature::verify(token, &jwks).ok_or(DashAuthorizationError)?;
        let now = self.now.as_ref()()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| DashAuthorizationError)?
            .as_secs_f64();
        validate_time_claims(&claims, now.floor())?;
        validate_api_key_hash(&claims, &self.api_key)?;
        if check_jti && !recently_issued(&claims, now) {
            self.check_jti(&claims).await?;
        }
        parse(&claims)
            .map(DashVerifiedClaims)
            .ok_or(DashAuthorizationError)
    }

    async fn check_jti(&self, claims: &Map<String, Value>) -> Result<(), DashAuthorizationError> {
        let mut body = Map::new();
        if let Some(jti) = claims.get("jti") {
            body.insert("jti".into(), jti.clone());
        }
        if let Some(exp) = claims.get("exp") {
            body.insert("expiresAt".into(), exp.clone());
        }
        let response = self
            .api
            .execute(DashRequest::post(
                "/api/auth/check-jti",
                Value::Object(body),
            ))
            .await
            .map_err(|_| DashAuthorizationError)?;
        if response.error.is_some()
            || response
                .data
                .as_ref()
                .and_then(|data| data.get("valid"))
                .and_then(Value::as_bool)
                != Some(true)
        {
            return Err(DashAuthorizationError);
        }
        Ok(())
    }
}

impl fmt::Debug for DashJwtVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DashJwtVerifier")
            .field("api_url", &self.api_url)
            .field("api_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

fn validate_time_claims(
    claims: &Map<String, Value>,
    now: f64,
) -> Result<(), DashAuthorizationError> {
    let issued_at = numeric_claim(claims, "iat").ok_or(DashAuthorizationError)?;
    let age = now - issued_at;
    if !age.is_finite() || !(0.0..=MAX_TOKEN_AGE_SECONDS).contains(&age) {
        return Err(DashAuthorizationError);
    }
    if numeric_claim(claims, "exp").is_some_and(|expires| expires <= now)
        || numeric_claim(claims, "nbf").is_some_and(|not_before| not_before > now)
    {
        return Err(DashAuthorizationError);
    }
    Ok(())
}

fn validate_api_key_hash(
    claims: &Map<String, Value>,
    api_key: &str,
) -> Result<(), DashAuthorizationError> {
    let expected = claims
        .get("apiKeyHash")
        .and_then(Value::as_str)
        .filter(|_| !api_key.is_empty())
        .ok_or(DashAuthorizationError)?;
    let actual = hex::encode(Sha256::digest(api_key.as_bytes()));
    if !constant_time_equal(expected.as_bytes(), actual.as_bytes()) {
        return Err(DashAuthorizationError);
    }
    Ok(())
}

fn recently_issued(claims: &Map<String, Value>, now: f64) -> bool {
    numeric_claim(claims, "iat")
        .is_some_and(|issued_at| issued_at != 0.0 && now - issued_at < JTI_GRACE_PERIOD_SECONDS)
}

fn numeric_claim(claims: &Map<String, Value>, name: &str) -> Option<f64> {
    claims.get(name).and_then(Value::as_f64)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let width = left.len().max(right.len());
    for index in 0..width {
        difference |= usize::from(left.get(index).copied().unwrap_or_default())
            ^ usize::from(right.get(index).copied().unwrap_or_default());
    }
    difference == 0
}

#[cfg(all(test, feature = "axum"))]
#[path = "jwt/contract.rs"]
mod contract;
