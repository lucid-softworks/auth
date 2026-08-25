use josekit::{
    jwk::Jwk,
    jws::{self, ES256, ES384, ES512, EdDSA, RS256},
};
use serde_json::Value;

use super::AgentJwtError;

pub(super) fn verify(
    token: &str,
    public_jwk: &Value,
    allowed_key_algorithms: &[String],
) -> Result<(), AgentJwtError> {
    let jwk = Jwk::from_bytes(
        &serde_json::to_vec(public_jwk).map_err(|_| AgentJwtError::InvalidPublicKey)?,
    )
    .map_err(|_| AgentJwtError::InvalidPublicKey)?;
    let key_algorithm = jwk
        .parameter("crv")
        .and_then(Value::as_str)
        .unwrap_or_else(|| jwk.key_type());
    if !allowed_key_algorithms
        .iter()
        .any(|allowed| allowed == key_algorithm)
    {
        return Err(AgentJwtError::UnsupportedAlgorithm);
    }
    if jwk.key_use().is_some_and(|usage| usage != "sig")
        || jwk
            .parameter("key_ops")
            .is_some_and(|operations| !permits_verification(operations))
    {
        return Err(AgentJwtError::InvalidPublicKey);
    }
    let result = match resolved_algorithm(&jwk) {
        Some("EdDSA") => jws::deserialize_compact(
            token,
            &EdDSA
                .verifier_from_jwk(&jwk)
                .map_err(|_| AgentJwtError::InvalidPublicKey)?,
        ),
        Some("ES256") => jws::deserialize_compact(
            token,
            &ES256
                .verifier_from_jwk(&jwk)
                .map_err(|_| AgentJwtError::InvalidPublicKey)?,
        ),
        Some("ES384") => jws::deserialize_compact(
            token,
            &ES384
                .verifier_from_jwk(&jwk)
                .map_err(|_| AgentJwtError::InvalidPublicKey)?,
        ),
        Some("ES512") => jws::deserialize_compact(
            token,
            &ES512
                .verifier_from_jwk(&jwk)
                .map_err(|_| AgentJwtError::InvalidPublicKey)?,
        ),
        Some("RS256") => jws::deserialize_compact(
            token,
            &RS256
                .verifier_from_jwk(&jwk)
                .map_err(|_| AgentJwtError::InvalidPublicKey)?,
        ),
        _ => return Err(AgentJwtError::InvalidPublicKey),
    };
    result
        .map(|_| ())
        .map_err(|_| AgentJwtError::InvalidSignature)
}

fn resolved_algorithm(jwk: &Jwk) -> Option<&'static str> {
    match jwk.parameter("crv").and_then(Value::as_str) {
        Some("Ed25519" | "Ed448") => Some("EdDSA"),
        Some("P-256") => Some("ES256"),
        Some("P-384") => Some("ES384"),
        Some("P-521") => Some("ES512"),
        Some(_) => None,
        None if jwk.key_type() == "OKP" => Some("EdDSA"),
        None if jwk.key_type() == "RSA" => Some("RS256"),
        None => Some("EdDSA"),
    }
}

fn permits_verification(value: &Value) -> bool {
    value.as_array().is_some_and(|operations| {
        operations
            .iter()
            .any(|value| value.as_str() == Some("verify"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::{
        jwk::{Ed25519, P_256},
        jws::{JwsHeader, JwsSigner},
    };

    fn sign(algorithm: &str, signer: &dyn JwsSigner) -> String {
        let mut header = JwsHeader::new();
        header.set_algorithm(algorithm);
        header.set_token_type("agent+jwt");
        jws::serialize_compact(br#"{"iat":1}"#, &header, signer).unwrap()
    }

    #[test]
    fn defaults_can_restrict_verification_to_ed25519_curve_names() {
        let ed = Jwk::generate_ed_key(Ed25519).unwrap();
        let ed_token = sign("EdDSA", &EdDSA.signer_from_jwk(&ed).unwrap());
        let ed_public = serde_json::to_value(ed.to_public_key().unwrap()).unwrap();
        assert!(verify(&ed_token, &ed_public, &["Ed25519".into()]).is_ok());

        let ec = Jwk::generate_ec_key(P_256).unwrap();
        let ec_token = sign("ES256", &ES256.signer_from_jwk(&ec).unwrap());
        let ec_public = serde_json::to_value(ec.to_public_key().unwrap()).unwrap();
        assert!(matches!(
            verify(&ec_token, &ec_public, &["Ed25519".into()]),
            Err(AgentJwtError::UnsupportedAlgorithm)
        ));
        assert!(verify(&ec_token, &ec_public, &["P-256".into()]).is_ok());
    }

    #[test]
    fn rejects_a_signature_from_another_key() {
        let signer = Jwk::generate_ed_key(Ed25519).unwrap();
        let other = Jwk::generate_ed_key(Ed25519).unwrap();
        let token = sign("EdDSA", &EdDSA.signer_from_jwk(&signer).unwrap());
        let public = serde_json::to_value(other.to_public_key().unwrap()).unwrap();
        assert!(matches!(
            verify(&token, &public, &["Ed25519".into()]),
            Err(AgentJwtError::InvalidSignature)
        ));
    }
}
