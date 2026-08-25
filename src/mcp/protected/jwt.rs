use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::jwk::JwkSet;
use serde_json::{Map, Value};

use super::{
    McpJwtVerifyOptions, McpProtectedRequestHandlerOptions, VerificationFailure, introspection,
};

mod jwks;

const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);
const JWKS_NO_KID_REFETCH_COOLDOWN: Duration = Duration::from_secs(30);

struct CachedJwks {
    body: Vec<u8>,
    fetched_at: Instant,
    no_kid_refetched_at: Option<Instant>,
}

fn jwks_cache() -> &'static Mutex<HashMap<String, CachedJwks>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CachedJwks>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) async fn verify_access_token(
    http: &reqwest::Client,
    token: &str,
    options: &McpProtectedRequestHandlerOptions,
) -> Result<Map<String, Value>, VerificationFailure> {
    let remote = options.remote_verify.as_ref();
    let mut payload = None;
    if let Some(jwks_url) = options.jwks_url.as_deref()
        && !remote.is_some_and(|remote| remote.force)
    {
        match verify_local(http, token, jwks_url, options).await {
            Ok(claims) => payload = Some(claims),
            Err(LocalFailure::Malformed) => {}
            Err(LocalFailure::Invalid) => {
                return Err(invalid_token("invalid access token"));
            }
            Err(LocalFailure::Expired) => return Err(invalid_token("token expired")),
            Err(LocalFailure::Infrastructure(message)) => {
                return Err(VerificationFailure::Infrastructure(message));
            }
        }
    }
    if let Some(remote) = remote {
        payload = Some(introspection::verify(http, token, remote, options).await?);
    }
    payload.ok_or_else(|| invalid_token("no token payload"))
}

async fn verify_local(
    http: &reqwest::Client,
    token: &str,
    jwks_url: &str,
    options: &McpProtectedRequestHandlerOptions,
) -> Result<Map<String, Value>, LocalFailure> {
    if token.split('.').count() != 3 {
        return Err(LocalFailure::Malformed);
    }
    let header: Value =
        decode_part(token.split('.').next().unwrap_or_default()).ok_or(LocalFailure::Malformed)?;
    let algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(LocalFailure::Malformed)?;
    if options
        .jwt_verify_options
        .algorithms
        .as_ref()
        .is_some_and(|allowed| !allowed.iter().any(|allowed| allowed == algorithm))
    {
        return Err(LocalFailure::Invalid);
    }
    if let Some(expected) = options.jwt_verify_options.token_type.as_deref()
        && !header
            .get("typ")
            .and_then(Value::as_str)
            .is_some_and(|actual| token_type_matches(actual, expected))
    {
        return Err(LocalFailure::Invalid);
    }
    let kid = header.get("kid").and_then(Value::as_str);
    let (body, from_cache) = cached_or_fetch_jwks(http, jwks_url, kid, false).await?;
    if let Some(payload) = jwks::verify(&body, token, algorithm, kid)? {
        return validated_local_claims(payload, options);
    }
    if kid.is_none() && from_cache && should_refetch_without_kid(jwks_url)? {
        let (body, _) = cached_or_fetch_jwks(http, jwks_url, None, true).await?;
        if let Some(payload) = jwks::verify(&body, token, algorithm, None)? {
            return validated_local_claims(payload, options);
        }
    }
    Err(LocalFailure::Invalid)
}

fn validated_local_claims(
    payload: Map<String, Value>,
    options: &McpProtectedRequestHandlerOptions,
) -> Result<Map<String, Value>, LocalFailure> {
    let mut payload = validate_claims(payload, options).map_err(map_claim_failure)?;
    if let Some(authorized_party) = payload.get("azp").filter(|value| js_truthy(value)).cloned() {
        payload.insert("client_id".into(), authorized_party);
    }
    Ok(payload)
}

fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value
            .as_f64()
            .is_some_and(|value| value != 0.0 && !value.is_nan()),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

async fn cached_or_fetch_jwks(
    http: &reqwest::Client,
    url: &str,
    kid: Option<&str>,
    force: bool,
) -> Result<(Vec<u8>, bool), LocalFailure> {
    if !force
        && let Some(body) = jwks_cache()
            .lock()
            .map_err(|_| LocalFailure::Infrastructure("JWKS cache lock failed".into()))?
            .get(url)
            .filter(|entry| entry.fetched_at.elapsed() < JWKS_CACHE_TTL)
            .filter(|entry| kid.is_none_or(|kid| jwks_contains_kid(&entry.body, kid)))
            .map(|entry| entry.body.clone())
    {
        return Ok((body, true));
    }
    let response = http
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|error| LocalFailure::Infrastructure(error.to_string()))?;
    if response.status().is_redirection() {
        return Err(LocalFailure::Infrastructure(format!(
            "The OAuth endpoint \"{url}\" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL."
        )));
    }
    if !response.status().is_success() {
        return Err(LocalFailure::Infrastructure(format!(
            "Jwks failed: {}",
            response.status()
        )));
    }
    let body = response
        .bytes()
        .await
        .map_err(|error| LocalFailure::Infrastructure(error.to_string()))?
        .to_vec();
    JwkSet::from_bytes(&body).map_err(|error| LocalFailure::Infrastructure(error.to_string()))?;
    jwks_cache()
        .lock()
        .map_err(|_| LocalFailure::Infrastructure("JWKS cache lock failed".into()))?
        .insert(
            url.into(),
            CachedJwks {
                body: body.clone(),
                fetched_at: Instant::now(),
                no_kid_refetched_at: (force && kid.is_none()).then(Instant::now),
            },
        );
    Ok((body, false))
}

fn should_refetch_without_kid(url: &str) -> Result<bool, LocalFailure> {
    let cache = jwks_cache()
        .lock()
        .map_err(|_| LocalFailure::Infrastructure("JWKS cache lock failed".into()))?;
    Ok(cache
        .get(url)
        .and_then(|entry| entry.no_kid_refetched_at)
        .is_none_or(|refetched| refetched.elapsed() >= JWKS_NO_KID_REFETCH_COOLDOWN))
}

fn map_claim_failure(failure: ClaimFailure) -> LocalFailure {
    match failure {
        ClaimFailure::Expired => LocalFailure::Expired,
        ClaimFailure::Invalid => LocalFailure::Invalid,
    }
}

fn jwks_contains_kid(body: &[u8], expected: &str) -> bool {
    JwkSet::from_bytes(body)
        .is_ok_and(|jwks| jwks.keys().iter().any(|jwk| jwk.key_id() == Some(expected)))
}

pub(super) fn validate_claims(
    payload: Map<String, Value>,
    options: &McpProtectedRequestHandlerOptions,
) -> Result<Map<String, Value>, ClaimFailure> {
    if payload.get("iss").and_then(Value::as_str) != Some(options.issuer.as_str())
        || !audience_matches(payload.get("aud"), &options.audience)
        || options
            .jwt_verify_options
            .subject
            .as_ref()
            .is_some_and(|subject| {
                payload.get("sub").and_then(Value::as_str) != Some(subject.as_str())
            })
    {
        return Err(ClaimFailure::Invalid);
    }
    validate_time_claims(&payload, &options.jwt_verify_options)?;
    for required in &options.jwt_verify_options.required_claims {
        if !payload.contains_key(required) {
            return Err(ClaimFailure::Invalid);
        }
    }
    Ok(payload)
}

fn validate_time_claims(
    payload: &Map<String, Value>,
    options: &McpJwtVerifyOptions,
) -> Result<(), ClaimFailure> {
    let now = options
        .current_date
        .unwrap_or_else(chrono::Utc::now)
        .timestamp_millis() as f64
        / 1_000.0;
    let tolerance = options.clock_tolerance_seconds;
    if let Some(expiration) = optional_number(payload, "exp")?
        && now - tolerance >= expiration
    {
        return Err(ClaimFailure::Expired);
    }
    if let Some(not_before) = optional_number(payload, "nbf")?
        && now + tolerance < not_before
    {
        return Err(ClaimFailure::Invalid);
    }
    if let Some(max_age) = options.max_token_age_seconds {
        let issued_at = optional_number(payload, "iat")?.ok_or(ClaimFailure::Invalid)?;
        let age = now - issued_at;
        if age - tolerance > max_age {
            return Err(ClaimFailure::Expired);
        }
        if age < -tolerance {
            return Err(ClaimFailure::Invalid);
        }
    }
    Ok(())
}

fn token_type_matches(actual: &str, expected: &str) -> bool {
    normalize_token_type(actual) == normalize_token_type(expected)
}

fn normalize_token_type(value: &str) -> String {
    let normalized = value.to_ascii_lowercase();
    if normalized.contains('/') {
        normalized
    } else {
        format!("application/{normalized}")
    }
}

fn optional_number(payload: &Map<String, Value>, name: &str) -> Result<Option<f64>, ClaimFailure> {
    match payload.get(name) {
        None => Ok(None),
        Some(value) => value
            .as_f64()
            .filter(|value| value.is_finite())
            .map(Some)
            .ok_or(ClaimFailure::Invalid),
    }
}

fn audience_matches(value: Option<&Value>, expected: &str) -> bool {
    match value {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn decode_part(value: &str) -> Option<Value> {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(value).ok()?).ok()
}

fn invalid_token(message: &str) -> VerificationFailure {
    VerificationFailure::Challenge(crate::OAuthProviderError::InvalidToken(message.into()))
}

#[derive(Debug)]
enum LocalFailure {
    Malformed,
    Invalid,
    Expired,
    Infrastructure(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClaimFailure {
    Invalid,
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn options() -> McpProtectedRequestHandlerOptions {
        McpProtectedRequestHandlerOptions {
            issuer: "https://auth.example.test".into(),
            audience: "https://api.example.test/mcp".into(),
            jwt_verify_options: McpJwtVerifyOptions::default(),
            jwks_url: None,
            remote_verify: None,
            required_scopes: None,
            challenge_scopes: None,
            is_scope_satisfied: None,
            dpop: Default::default(),
        }
    }

    #[test]
    fn validates_authoritative_issuer_audience_and_optional_expiry() {
        let mut payload = Map::from_iter([
            (
                "iss".into(),
                Value::String("https://auth.example.test".into()),
            ),
            (
                "aud".into(),
                Value::String("https://api.example.test/mcp".into()),
            ),
        ]);
        assert!(validate_claims(payload.clone(), &options()).is_ok());
        payload.insert("aud".into(), Value::String("https://other.example".into()));
        assert_eq!(
            validate_claims(payload, &options()),
            Err(ClaimFailure::Invalid)
        );
    }

    #[test]
    fn cached_key_sets_must_contain_the_requested_kid() {
        let body = br#"{"keys":[{"kty":"RSA","kid":"current","e":"AQAB","n":"sXch"}]}"#;
        assert!(jwks_contains_kid(body, "current"));
        assert!(!jwks_contains_kid(body, "rotated"));
    }

    #[test]
    fn jose_claim_overrides_match_subject_type_and_token_age_semantics() {
        assert!(token_type_matches("JWT", "application/jwt"));
        assert!(token_type_matches(
            "Application/At+JWT",
            "application/at+jwt"
        ));

        let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let mut options = options();
        options.jwt_verify_options.subject = Some("expected-subject".into());
        options.jwt_verify_options.max_token_age_seconds = Some(60.0);
        options.jwt_verify_options.current_date = Some(now);
        let claims = |subject: &str, issued_at: i64| {
            Map::from_iter([
                ("iss".into(), json!(options.issuer)),
                ("aud".into(), json!(options.audience)),
                ("sub".into(), json!(subject)),
                ("iat".into(), json!(issued_at)),
            ])
        };

        assert!(validate_claims(claims("expected-subject", now.timestamp()), &options).is_ok());
        assert_eq!(
            validate_claims(claims("other-subject", now.timestamp()), &options),
            Err(ClaimFailure::Invalid)
        );
        assert_eq!(
            validate_claims(claims("expected-subject", now.timestamp() - 61), &options),
            Err(ClaimFailure::Expired)
        );
        assert_eq!(
            validate_claims(claims("expected-subject", now.timestamp() + 1), &options),
            Err(ClaimFailure::Invalid)
        );
    }
}
