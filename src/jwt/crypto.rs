use super::{JwkAlgorithm, JwtError, JwtProtectedHeader};
use crate::AuthError;
use josekit::{
    jwk::{Ed25519, Jwk, P_256, P_521},
    jws::{self, ES256, ES512, EdDSA, JwsHeader, PS256, RS256},
};
use serde_json::{Map, Value};

#[derive(Clone, PartialEq)]
pub struct ExportedKeyPair {
    pub public_web_key: Value,
    pub private_web_key: Value,
    pub alg: String,
    pub crv: Option<String>,
}

impl std::fmt::Debug for ExportedKeyPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExportedKeyPair")
            .field("public_web_key", &self.public_web_key)
            .field("private_web_key", &"[REDACTED]")
            .field("alg", &self.alg)
            .field("crv", &self.crv)
            .finish()
    }
}

pub fn generate_exported_key_pair(algorithm: JwkAlgorithm) -> Result<ExportedKeyPair, AuthError> {
    let private = match algorithm {
        JwkAlgorithm::EdDsa => Jwk::generate_ed_key(Ed25519),
        JwkAlgorithm::Es256 => Jwk::generate_ec_key(P_256),
        JwkAlgorithm::Es512 => Jwk::generate_ec_key(P_521),
        JwkAlgorithm::Ps256 { modulus_length } | JwkAlgorithm::Rs256 { modulus_length } => {
            Jwk::generate_rsa_key(modulus_length.unwrap_or(2_048))
        }
    }
    .map_err(|_| JwtError::KeyGeneration)?;
    let public = private
        .to_public_key()
        .map_err(|_| JwtError::KeyGeneration)?;
    Ok(ExportedKeyPair {
        public_web_key: serde_json::to_value(public).map_err(key_json)?,
        private_web_key: serde_json::to_value(private).map_err(key_json)?,
        alg: algorithm.name().into(),
        crv: algorithm.curve().map(str::to_owned),
    })
}

pub(crate) fn sign_compact(
    payload: &Map<String, Value>,
    protected: Option<&JwtProtectedHeader>,
    algorithm: JwkAlgorithm,
    kid: &str,
    private_jwk: &str,
) -> Result<String, AuthError> {
    let key = Jwk::from_bytes(private_jwk).map_err(|_| JwtError::Signing)?;
    let mut header = JwsHeader::new();
    if let Some(typ) = protected.and_then(|value| value.typ.as_deref()) {
        header.set_token_type(typ);
    }
    if let Some(cty) = protected.and_then(|value| value.cty.as_deref()) {
        header.set_content_type(cty);
    }
    header.set_algorithm(algorithm.name());
    header.set_key_id(kid);
    let payload = serde_json::to_vec(payload).map_err(key_json)?;
    match algorithm {
        JwkAlgorithm::EdDsa => jws::serialize_compact(
            &payload,
            &header,
            &EdDSA.signer_from_jwk(&key).map_err(|_| JwtError::Signing)?,
        ),
        JwkAlgorithm::Es256 => jws::serialize_compact(
            &payload,
            &header,
            &ES256.signer_from_jwk(&key).map_err(|_| JwtError::Signing)?,
        ),
        JwkAlgorithm::Es512 => jws::serialize_compact(
            &payload,
            &header,
            &ES512.signer_from_jwk(&key).map_err(|_| JwtError::Signing)?,
        ),
        JwkAlgorithm::Ps256 { .. } => jws::serialize_compact(
            &payload,
            &header,
            &PS256.signer_from_jwk(&key).map_err(|_| JwtError::Signing)?,
        ),
        JwkAlgorithm::Rs256 { .. } => jws::serialize_compact(
            &payload,
            &header,
            &RS256.signer_from_jwk(&key).map_err(|_| JwtError::Signing)?,
        ),
    }
    .map_err(|_| JwtError::Signing.into())
}

pub(crate) fn verify_compact(
    token: &str,
    algorithm: JwkAlgorithm,
    public_jwk: &str,
) -> Option<Map<String, Value>> {
    let key = Jwk::from_bytes(public_jwk).ok()?;
    let result = match algorithm {
        JwkAlgorithm::EdDsa => {
            jws::deserialize_compact(token, &EdDSA.verifier_from_jwk(&key).ok()?)
        }
        JwkAlgorithm::Es256 => {
            jws::deserialize_compact(token, &ES256.verifier_from_jwk(&key).ok()?)
        }
        JwkAlgorithm::Es512 => {
            jws::deserialize_compact(token, &ES512.verifier_from_jwk(&key).ok()?)
        }
        JwkAlgorithm::Ps256 { .. } => {
            jws::deserialize_compact(token, &PS256.verifier_from_jwk(&key).ok()?)
        }
        JwkAlgorithm::Rs256 { .. } => {
            jws::deserialize_compact(token, &RS256.verifier_from_jwk(&key).ok()?)
        }
    }
    .ok()?;
    serde_json::from_slice(&result.0).ok()
}

pub(crate) fn algorithm_from_name(name: &str) -> Option<JwkAlgorithm> {
    match name {
        "EdDSA" => Some(JwkAlgorithm::EdDsa),
        "ES256" => Some(JwkAlgorithm::Es256),
        "ES512" => Some(JwkAlgorithm::Es512),
        "PS256" => Some(JwkAlgorithm::Ps256 {
            modulus_length: None,
        }),
        "RS256" => Some(JwkAlgorithm::Rs256 {
            modulus_length: None,
        }),
        _ => None,
    }
}

fn key_json(error: serde_json::Error) -> AuthError {
    AuthError::Storage(format!("JWT key JSON failed: {error}"))
}
