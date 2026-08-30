use super::OidcConfig;
use crate::AuthError;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::{
    jwk::{Jwk, JwkSet},
    jws::{
        ES256, ES256K, ES384, ES512, EdDSA, HS256, HS384, HS512, JwsVerifier, PS256, PS384, PS512,
        RS256, RS384, RS512,
    },
    jwt,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct TokenHeader {
    alg: String,
    kid: Option<String>,
}

pub(crate) async fn verify_id_token(
    token: &str,
    oidc: &OidcConfig,
    expected_nonce: Option<&str>,
) -> Result<Value, AuthError> {
    let header = token_header(token)?;
    if !oidc.algorithms.is_empty() && !oidc.algorithms.contains(&header.alg) {
        return Err(AuthError::OAuthInvalidToken);
    }
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| AuthError::OAuthInvalidToken)?
        .get(&oidc.jwks_url)
        .send()
        .await
        .map_err(|_| AuthError::OAuthInvalidToken)?;
    if !response.status().is_success() || response.status().is_redirection() {
        return Err(AuthError::OAuthInvalidToken);
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| AuthError::OAuthInvalidToken)?;
    let jwks = JwkSet::from_bytes(&bytes).map_err(|_| AuthError::OAuthInvalidToken)?;
    let candidates = match header.kid.as_deref() {
        Some(kid) => jwks.get(kid),
        None => jwks.keys(),
    };
    let mut verifiers = candidates
        .into_iter()
        .filter(|jwk| {
            jwk.algorithm()
                .is_none_or(|algorithm| algorithm == header.alg)
        })
        .filter_map(|jwk| verifier(&header.alg, jwk, header.kid.is_none()))
        .collect::<Vec<_>>();
    if header.kid.is_none() && verifiers.len() != 1 {
        return Err(AuthError::OAuthInvalidToken);
    }
    for verifier in verifiers.drain(..) {
        if let Ok((payload, _)) = jwt::decode_with_verifier(token, verifier.as_ref()) {
            let claims = Value::Object(payload.as_ref().clone());
            validate_claims(&claims, oidc, expected_nonce)?;
            return Ok(claims);
        }
    }
    Err(AuthError::OAuthInvalidToken)
}

fn token_header(token: &str) -> Result<TokenHeader, AuthError> {
    let encoded = token
        .split('.')
        .next()
        .ok_or(AuthError::OAuthInvalidToken)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AuthError::OAuthInvalidToken)?;
    serde_json::from_slice(&bytes).map_err(|_| AuthError::OAuthInvalidToken)
}

fn verifier(algorithm: &str, jwk: &Jwk, ignore_key_id: bool) -> Option<Box<dyn JwsVerifier>> {
    let mut key = jwk.clone();
    if ignore_key_id {
        key.set_parameter("kid", None).ok()?;
    }
    let jwk = &key;
    Some(match algorithm {
        "HS256" => Box::new(HS256.verifier_from_jwk(jwk).ok()?),
        "HS384" => Box::new(HS384.verifier_from_jwk(jwk).ok()?),
        "HS512" => Box::new(HS512.verifier_from_jwk(jwk).ok()?),
        "ES256" => Box::new(ES256.verifier_from_jwk(jwk).ok()?),
        "ES256K" => Box::new(ES256K.verifier_from_jwk(jwk).ok()?),
        "ES384" => Box::new(ES384.verifier_from_jwk(jwk).ok()?),
        "ES512" => Box::new(ES512.verifier_from_jwk(jwk).ok()?),
        "RS256" => Box::new(RS256.verifier_from_jwk(jwk).ok()?),
        "RS384" => Box::new(RS384.verifier_from_jwk(jwk).ok()?),
        "RS512" => Box::new(RS512.verifier_from_jwk(jwk).ok()?),
        "PS256" => Box::new(PS256.verifier_from_jwk(jwk).ok()?),
        "PS384" => Box::new(PS384.verifier_from_jwk(jwk).ok()?),
        "PS512" => Box::new(PS512.verifier_from_jwk(jwk).ok()?),
        "EdDSA" => Box::new(EdDSA.verifier_from_jwk(jwk).ok()?),
        _ => return None,
    })
}

fn validate_claims(
    claims: &Value,
    oidc: &OidcConfig,
    expected_nonce: Option<&str>,
) -> Result<(), AuthError> {
    let now = chrono::Utc::now().timestamp();
    if let Some(expires) = numeric_date(claims, "exp")?
        && expires <= now
    {
        return Err(AuthError::OAuthInvalidToken);
    }
    if let Some(not_before) = numeric_date(claims, "nbf")?
        && not_before > now
    {
        return Err(AuthError::OAuthInvalidToken);
    }
    validate_issuer(claims, oidc)?;
    validate_audience(claims, &oidc.audiences)?;
    validate_authorized_party(claims, &oidc.audiences)?;
    validate_maximum_age(claims, oidc, now)?;
    validate_nonce(claims, oidc, expected_nonce)
}

fn validate_authorized_party(claims: &Value, expected: &[String]) -> Result<(), AuthError> {
    let [client_id] = expected else {
        return Ok(());
    };
    let multiple_audiences = claims
        .get("aud")
        .and_then(Value::as_array)
        .is_some_and(|audiences| audiences.len() > 1);
    let authorized_party = claims.get("azp").and_then(Value::as_str);
    if (multiple_audiences && authorized_party.is_none())
        || authorized_party.is_some_and(|party| party != client_id)
    {
        return Err(AuthError::OAuthInvalidToken);
    }
    Ok(())
}

fn validate_issuer(claims: &Value, oidc: &OidcConfig) -> Result<(), AuthError> {
    let issuer = claims.get("iss").and_then(Value::as_str);
    if !oidc.issuers.is_empty()
        && issuer.is_none_or(|issuer| !oidc.issuers.iter().any(|value| value == issuer))
    {
        return Err(AuthError::OAuthInvalidToken);
    }
    if let Some(template) = &oidc.dynamic_issuer_template {
        let tenant = claims
            .get("tid")
            .and_then(Value::as_str)
            .ok_or(AuthError::OAuthInvalidToken)?;
        if issuer != Some(template.replace("{tid}", tenant).as_str()) {
            return Err(AuthError::OAuthInvalidToken);
        }
    }
    Ok(())
}

fn validate_audience(claims: &Value, expected: &[String]) -> Result<(), AuthError> {
    if expected.is_empty() {
        return Ok(());
    }
    let matches = match claims.get("aud") {
        Some(Value::String(value)) => expected.contains(value),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .any(|value| expected.iter().any(|expected| expected == value)),
        _ => false,
    };
    matches.then_some(()).ok_or(AuthError::OAuthInvalidToken)
}

fn validate_maximum_age(claims: &Value, oidc: &OidcConfig, now: i64) -> Result<(), AuthError> {
    let Some(maximum_age) = oidc.maximum_age else {
        return Ok(());
    };
    for required in ["exp", "iat", "iss", "aud", "sub"] {
        if claims.get(required).is_none() {
            return Err(AuthError::OAuthInvalidToken);
        }
    }
    let issued_at = numeric_date(claims, "iat")?.ok_or(AuthError::OAuthInvalidToken)?;
    if issued_at > now || now - issued_at > maximum_age.num_seconds() {
        return Err(AuthError::OAuthInvalidToken);
    }
    Ok(())
}

fn validate_nonce(
    claims: &Value,
    oidc: &OidcConfig,
    expected: Option<&str>,
) -> Result<(), AuthError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let actual = claims.get("nonce").and_then(Value::as_str);
    let hashed = hex::encode(Sha256::digest(expected.as_bytes()));
    if actual != Some(expected) && !(oidc.nonce_sha256_fallback && actual == Some(hashed.as_str()))
    {
        return Err(AuthError::OAuthInvalidToken);
    }
    Ok(())
}

fn numeric_date(claims: &Value, name: &str) -> Result<Option<i64>, AuthError> {
    match claims.get(name) {
        None => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or(AuthError::OAuthInvalidToken),
    }
}
