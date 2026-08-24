use super::{
    JwtAdapterContext, JwtConfig, JwtProtectedHeader, JwtSigningOverrides, crypto, keyring,
};
use crate::{AuthError, AuthService, session_cache::SessionCachePayload};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use serde_json::{Map, Value};

const TYPE: &str = "better-auth.session-cache+jwt";
const AUDIENCE: &str = "better-auth:session-cache";
const FALLBACK_ISSUER: &str = "better-auth:session-cache";
const CLOCK_TOLERANCE_SECONDS: f64 = 15.0;

pub(crate) async fn encode(
    service: &AuthService,
    config: &JwtConfig,
    payload: SessionCachePayload,
    max_age_seconds: i64,
) -> Result<String, AuthError> {
    let session_token = required_string(&payload.session, "token")?.to_owned();
    let user_id = required_string(&payload.user, "id")?.to_owned();
    let now = Utc::now().timestamp();
    let mut claims = serde_json::to_value(payload)
        .map_err(cache_json)?
        .as_object()
        .cloned()
        .ok_or_else(|| cache_error("invalid cookie-cache payload"))?;
    claims.insert("sid".into(), Value::String(session_token));
    claims.insert("iat".into(), Value::Number(now.into()));
    claims.insert(
        "exp".into(),
        Value::Number(now.saturating_add(max_age_seconds).into()),
    );
    claims.insert("iss".into(), Value::String(issuer(service)));
    claims.insert("aud".into(), Value::String(AUDIENCE.into()));
    claims.insert("sub".into(), Value::String(user_id));

    let resolved = keyring::resolve(
        service,
        config,
        &JwtAdapterContext::default(),
        &JwtSigningOverrides::default(),
    )
    .await?
    .ok_or_else(|| cache_error("JWT cookie cache requires locally managed keys"))?;
    let algorithm = crypto::algorithm_from_name(&resolved.alg)
        .ok_or_else(|| cache_error("unsupported cookie-cache JWT algorithm"))?;
    crypto::sign_compact(
        &claims,
        Some(&JwtProtectedHeader {
            typ: Some(TYPE.into()),
            cty: None,
        }),
        algorithm,
        &resolved.kid,
        &resolved.key.private_key,
    )
}

pub(crate) async fn decode(
    service: &AuthService,
    config: &JwtConfig,
    token: &str,
) -> Option<(SessionCachePayload, i64)> {
    let header = protected_header(token)?;
    if header.get("typ")?.as_str()? != TYPE {
        return None;
    }
    let kid = header.get("kid")?.as_str()?.to_owned();
    let keys = keyring::all_keys(service, config, &JwtAdapterContext::default())
        .await
        .ok()?;
    let key = keys.iter().find(|key| key.id == kid)?;
    let algorithm = key
        .alg
        .as_deref()
        .and_then(crypto::algorithm_from_name)
        .or(config.jwks.key_pair_config)
        .or_else(|| {
            header
                .get("alg")
                .and_then(Value::as_str)
                .and_then(crypto::algorithm_from_name)
        })?;
    if header.get("alg")?.as_str()? != algorithm.name() {
        return None;
    }
    let claims = crypto::verify_compact(token, algorithm, &key.public_key)?;
    validate_registered_claims(service, &claims)?;
    let payload: SessionCachePayload =
        serde_json::from_value(Value::Object(claims.clone())).ok()?;
    let session_token = required_string(&payload.session, "token").ok()?;
    let user_id = required_string(&payload.user, "id").ok()?;
    if claims.get("sid")?.as_str()? != session_token || claims.get("sub")?.as_str()? != user_id {
        return None;
    }
    let expires_at = claims
        .get("exp")
        .and_then(Value::as_f64)
        .map(|value| (value * 1_000.0) as i64)
        .unwrap_or_else(|| Utc::now().timestamp_millis());
    Some((payload, expires_at))
}

fn validate_registered_claims(service: &AuthService, claims: &Map<String, Value>) -> Option<()> {
    if claims
        .get("iss")?
        .as_str()
        .filter(|value| !value.is_empty())?
        != issuer(service)
        || !audience_matches(claims.get("aud")?)
    {
        return None;
    }
    let now = Utc::now().timestamp() as f64;
    if let Some(exp) = numeric_claim(claims, "exp")?
        && exp <= now - CLOCK_TOLERANCE_SECONDS
    {
        return None;
    }
    if let Some(nbf) = numeric_claim(claims, "nbf")?
        && nbf > now + CLOCK_TOLERANCE_SECONDS
    {
        return None;
    }
    Some(())
}

fn audience_matches(value: &Value) -> bool {
    match value {
        Value::String(value) => value == AUDIENCE,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(AUDIENCE)),
        _ => false,
    }
}

fn numeric_claim(claims: &Map<String, Value>, name: &str) -> Option<Option<f64>> {
    match claims.get(name) {
        None => Some(None),
        Some(value) => value.as_f64().map(Some),
    }
}

fn protected_header(token: &str) -> Option<Map<String, Value>> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    parts.next()?;
    parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()
}

fn issuer(service: &AuthService) -> String {
    service
        .jwt_default_origin()
        .unwrap_or_else(|| FALLBACK_ISSUER.into())
}

fn required_string<'a>(value: &'a Value, name: &str) -> Result<&'a str, AuthError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| cache_error("cookie-cache session identity is missing"))
}

fn cache_json(error: serde_json::Error) -> AuthError {
    AuthError::Storage(format!("session cookie-cache JSON failed: {error}"))
}

fn cache_error(message: &str) -> AuthError {
    AuthError::InvalidConfiguration(message.into())
}
