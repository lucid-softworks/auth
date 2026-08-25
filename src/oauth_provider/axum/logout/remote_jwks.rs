use crate::oauth_provider::OAuthProviderError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::jwk::{Jwk, JwkSet};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::time::Duration;

const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
struct ProtectedHeader {
    alg: String,
    kid: Option<String>,
}

pub(super) async fn verify(
    remote_url: &str,
    token: &str,
) -> Result<Option<Map<String, Value>>, OAuthProviderError> {
    let header = decode_header(token).ok_or_else(verification_error)?;
    let jwks = fetch_jwks(remote_url).await?;
    for jwk in jwks.keys().into_iter().filter(|jwk| {
        header
            .kid
            .as_deref()
            .is_none_or(|kid| jwk.key_id() == Some(kid))
            && jwk
                .algorithm()
                .is_none_or(|algorithm| algorithm == header.alg)
    }) {
        let Some(verifier) = verifier(&header.alg, jwk) else {
            continue;
        };
        if let Ok((payload, _)) = josekit::jwt::decode_with_verifier(token, verifier.as_ref()) {
            return Ok(Some(payload.as_ref().clone()));
        }
    }
    Ok(None)
}

async fn fetch_jwks(remote_url: &str) -> Result<JwkSet, OAuthProviderError> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|_| verification_error())?;
    let mut response = client
        .get(remote_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| verification_error())?;
    if response.status() != reqwest::StatusCode::OK
        || response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(verification_error());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| verification_error())? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(verification_error());
        }
        body.extend_from_slice(&chunk);
    }
    JwkSet::from_bytes(&body).map_err(|_| verification_error())
}

fn decode_header(token: &str) -> Option<ProtectedHeader> {
    let encoded = token.split('.').next()?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).ok()?).ok()
}

fn verifier(algorithm: &str, jwk: &Jwk) -> Option<Box<dyn josekit::jws::JwsVerifier>> {
    use josekit::jws::{ES256, ES512, EdDSA, PS256, RS256};
    Some(match algorithm {
        "EdDSA" => Box::new(EdDSA.verifier_from_jwk(jwk).ok()?),
        "ES256" => Box::new(ES256.verifier_from_jwk(jwk).ok()?),
        "ES512" => Box::new(ES512.verifier_from_jwk(jwk).ok()?),
        "PS256" => Box::new(PS256.verifier_from_jwk(jwk).ok()?),
        "RS256" => Box::new(RS256.verifier_from_jwk(jwk).ok()?),
        _ => return None,
    })
}

fn verification_error() -> OAuthProviderError {
    OAuthProviderError::ServerError("Unable to verify the id_token_hint".into())
}
