use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use josekit::jwk::{Jwk, JwkSet};
use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Deserialize)]
struct ProtectedHeader {
    alg: String,
    kid: Option<String>,
}

pub(super) fn verify(token: &str, jwks: &Value) -> Option<Map<String, Value>> {
    let header = decode_header(token)?;
    let bytes = serde_json::to_vec(jwks).ok()?;
    let keys = JwkSet::from_bytes(&bytes).ok()?;
    for key in keys.keys().into_iter().filter(|key| {
        header
            .kid
            .as_deref()
            .is_none_or(|kid| key.key_id() == Some(kid))
            && key
                .algorithm()
                .is_none_or(|algorithm| algorithm == header.alg)
    }) {
        let Some(verifier) = verifier(&header.alg, key) else {
            continue;
        };
        if let Ok((payload, _)) = josekit::jwt::decode_with_verifier(token, verifier.as_ref()) {
            return Some(payload.as_ref().clone());
        }
    }
    None
}

fn decode_header(token: &str) -> Option<ProtectedHeader> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    parts.next()?;
    parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()
}

fn verifier(algorithm: &str, jwk: &Jwk) -> Option<Box<dyn josekit::jws::JwsVerifier>> {
    use josekit::jws::{ES256, ES384, ES512, EdDSA, PS256, PS384, PS512, RS256, RS384, RS512};
    Some(match algorithm {
        "RS256" => Box::new(RS256.verifier_from_jwk(jwk).ok()?),
        "RS384" => Box::new(RS384.verifier_from_jwk(jwk).ok()?),
        "RS512" => Box::new(RS512.verifier_from_jwk(jwk).ok()?),
        "PS256" => Box::new(PS256.verifier_from_jwk(jwk).ok()?),
        "PS384" => Box::new(PS384.verifier_from_jwk(jwk).ok()?),
        "PS512" => Box::new(PS512.verifier_from_jwk(jwk).ok()?),
        "ES256" => Box::new(ES256.verifier_from_jwk(jwk).ok()?),
        "ES384" => Box::new(ES384.verifier_from_jwk(jwk).ok()?),
        "ES512" => Box::new(ES512.verifier_from_jwk(jwk).ok()?),
        "EdDSA" => Box::new(EdDSA.verifier_from_jwk(jwk).ok()?),
        _ => return None,
    })
}
