use josekit::{
    jwk::{Jwk, JwkSet},
    jws::{self, ES256, ES384, ES512, EdDSA, PS256, PS384, PS512, RS256, RS384, RS512},
};
use serde_json::{Map, Value};

use super::LocalFailure;

pub(super) fn verify(
    body: &[u8],
    token: &str,
    algorithm: &str,
    kid: Option<&str>,
) -> Result<Option<Map<String, Value>>, LocalFailure> {
    let jwks = JwkSet::from_bytes(body)
        .map_err(|error| LocalFailure::Infrastructure(error.to_string()))?;
    let candidates: Vec<_> = jwks
        .keys()
        .into_iter()
        .filter(|jwk| {
            kid.is_none_or(|kid| jwk.key_id() == Some(kid))
                && jwk
                    .algorithm()
                    .is_none_or(|configured| configured == algorithm)
                && usable_for_algorithm(jwk, algorithm)
        })
        .collect();
    if kid.is_none() && candidates.len() > 1 {
        return Err(LocalFailure::Infrastructure(
            "multiple matching keys found in the JSON Web Key Set".into(),
        ));
    }
    for jwk in candidates {
        if let Some(payload) = verify_with_jwk(token, algorithm, jwk) {
            return Ok(Some(payload));
        }
    }
    Ok(None)
}

fn verify_with_jwk(token: &str, algorithm: &str, jwk: &Jwk) -> Option<Map<String, Value>> {
    let verified = match algorithm {
        "EdDSA" => jws::deserialize_compact(token, &EdDSA.verifier_from_jwk(jwk).ok()?),
        "ES256" => jws::deserialize_compact(token, &ES256.verifier_from_jwk(jwk).ok()?),
        "ES384" => jws::deserialize_compact(token, &ES384.verifier_from_jwk(jwk).ok()?),
        "ES512" => jws::deserialize_compact(token, &ES512.verifier_from_jwk(jwk).ok()?),
        "PS256" => jws::deserialize_compact(token, &PS256.verifier_from_jwk(jwk).ok()?),
        "PS384" => jws::deserialize_compact(token, &PS384.verifier_from_jwk(jwk).ok()?),
        "PS512" => jws::deserialize_compact(token, &PS512.verifier_from_jwk(jwk).ok()?),
        "RS256" => jws::deserialize_compact(token, &RS256.verifier_from_jwk(jwk).ok()?),
        "RS384" => jws::deserialize_compact(token, &RS384.verifier_from_jwk(jwk).ok()?),
        "RS512" => jws::deserialize_compact(token, &RS512.verifier_from_jwk(jwk).ok()?),
        _ => return None,
    }
    .ok()?;
    serde_json::from_slice(&verified.0).ok()
}

fn usable_for_algorithm(jwk: &Jwk, algorithm: &str) -> bool {
    if jwk.key_use().is_some_and(|usage| usage != "sig")
        || !valid_verify_operations(jwk.parameter("key_ops"))
    {
        return false;
    }
    match algorithm {
        "EdDSA" => {
            jwk.key_type() == "OKP"
                && jwk.parameter("crv").and_then(Value::as_str) == Some("Ed25519")
        }
        "ES256" => ec_curve_matches(jwk, "P-256"),
        "ES384" => ec_curve_matches(jwk, "P-384"),
        "ES512" => ec_curve_matches(jwk, "P-521"),
        "PS256" | "PS384" | "PS512" | "RS256" | "RS384" | "RS512" => jwk.key_type() == "RSA",
        _ => false,
    }
}

fn ec_curve_matches(jwk: &Jwk, expected: &str) -> bool {
    jwk.key_type() == "EC" && jwk.parameter("crv").and_then(Value::as_str) == Some(expected)
}

fn valid_verify_operations(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return true;
    };
    let Some(operations) = value.as_array() else {
        return false;
    };
    let mut seen = std::collections::BTreeSet::new();
    operations
        .iter()
        .map(Value::as_str)
        .all(|operation| operation.is_some_and(|operation| seen.insert(operation)))
        && seen.contains("verify")
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::{
        jwk::P_256,
        jws::{ES256, JwsHeader},
    };
    use serde_json::json;

    #[test]
    fn no_kid_selection_filters_mixed_key_types_before_cardinality() {
        let rsa = Jwk::generate_rsa_key(2_048)
            .unwrap()
            .to_public_key()
            .unwrap();
        let private = Jwk::generate_ec_key(P_256).unwrap();
        let public = private.to_public_key().unwrap();
        let mut header = JwsHeader::new();
        header.set_algorithm("ES256");
        let token = jws::serialize_compact(
            br#"{"sub":"mixed-key"}"#,
            &header,
            &ES256.signer_from_jwk(&private).unwrap(),
        )
        .unwrap();
        let body = serde_json::to_vec(&json!({"keys": [rsa, public]})).unwrap();

        assert_eq!(
            verify(&body, &token, "ES256", None).unwrap().unwrap()["sub"],
            "mixed-key"
        );
    }
}
