use josekit::{
    jwk::Jwk,
    jws::{self, ES256, ES384, ES512, EdDSA, PS256, PS384, PS512, RS256, RS384, RS512},
};
use serde_json::{Map, Value};

use super::{VerificationFailure, invalid_dpop};

pub(super) fn verify(
    proof: &str,
    algorithm: &str,
    jwk: &Jwk,
) -> Result<Map<String, Value>, VerificationFailure> {
    let verified = match algorithm {
        "EdDSA" => jws::deserialize_compact(proof, &EdDSA.verifier_from_jwk(jwk).map_err(error)?),
        "ES256" => jws::deserialize_compact(proof, &ES256.verifier_from_jwk(jwk).map_err(error)?),
        "ES384" => jws::deserialize_compact(proof, &ES384.verifier_from_jwk(jwk).map_err(error)?),
        "ES512" => jws::deserialize_compact(proof, &ES512.verifier_from_jwk(jwk).map_err(error)?),
        "PS256" => jws::deserialize_compact(proof, &PS256.verifier_from_jwk(jwk).map_err(error)?),
        "PS384" => jws::deserialize_compact(proof, &PS384.verifier_from_jwk(jwk).map_err(error)?),
        "PS512" => jws::deserialize_compact(proof, &PS512.verifier_from_jwk(jwk).map_err(error)?),
        "RS256" => jws::deserialize_compact(proof, &RS256.verifier_from_jwk(jwk).map_err(error)?),
        "RS384" => jws::deserialize_compact(proof, &RS384.verifier_from_jwk(jwk).map_err(error)?),
        "RS512" => jws::deserialize_compact(proof, &RS512.verifier_from_jwk(jwk).map_err(error)?),
        _ => return Err(invalid_dpop("DPoP proof uses an unsupported JWS algorithm")),
    }
    .map_err(error)?;
    serde_json::from_slice(&verified.0).map_err(|_| invalid_dpop("DPoP proof signature is invalid"))
}

fn error(error: impl std::fmt::Display) -> VerificationFailure {
    invalid_dpop(&error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::{
        jwk::P_384,
        jws::{ES384, JwsHeader},
    };
    use serde_json::json;

    #[test]
    fn explicitly_allowed_es384_proofs_use_the_full_jose_verifier_set() {
        let private = Jwk::generate_ec_key(P_384).unwrap();
        let public = private.to_public_key().unwrap();
        let mut header = JwsHeader::new();
        header.set_algorithm("ES384");
        header.set_token_type("dpop+jwt");
        header.set_jwk(public);
        let proof = jws::serialize_compact(
            &serde_json::to_vec(&json!({"proof": true})).unwrap(),
            &header,
            &ES384.signer_from_jwk(&private).unwrap(),
        )
        .unwrap();

        assert_eq!(verify(&proof, "ES384", &private).unwrap()["proof"], true);
    }
}
