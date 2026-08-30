use serde_json::{Map, Value};

const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth"];
const RSA_ALGORITHMS: &[&str] = &["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"];

pub(super) fn validate_public_jwks(value: &Value) -> bool {
    let Some(keys) = value
        .as_object()
        .and_then(|object| object.get("keys"))
        .and_then(Value::as_array)
        .filter(|keys| !keys.is_empty())
    else {
        return false;
    };
    keys.iter().all(|key| {
        key.as_object()
            .is_some_and(|key| is_public(key) && has_supported_shape(key) && algorithm_matches(key))
    })
}

fn is_public(key: &Map<String, Value>) -> bool {
    key.get("kty").and_then(Value::as_str) != Some("oct")
        && !key.contains_key("k")
        && !PRIVATE_MEMBERS.iter().any(|name| key.contains_key(*name))
}

fn has_supported_shape(key: &Map<String, Value>) -> bool {
    match string(key, "kty") {
        Some("RSA") => nonempty(key, "n") && nonempty(key, "e"),
        Some("EC") => {
            matches!(string(key, "crv"), Some("P-256" | "P-384" | "P-521"))
                && nonempty(key, "x")
                && nonempty(key, "y")
        }
        Some("OKP") => string(key, "crv") == Some("Ed25519") && nonempty(key, "x"),
        _ => false,
    }
}

fn algorithm_matches(key: &Map<String, Value>) -> bool {
    let Some(algorithm) = key.get("alg") else {
        return true;
    };
    let Some(algorithm) = algorithm.as_str() else {
        return false;
    };
    match string(key, "kty") {
        Some("RSA") => RSA_ALGORITHMS.contains(&algorithm),
        Some("EC") => matches!(
            (string(key, "crv"), algorithm),
            (Some("P-256"), "ES256")
                | (Some("P-384"), "ES384")
                | (Some("P-521"), "ES512")
        ),
        Some("OKP") => string(key, "crv") == Some("Ed25519") && algorithm == "EdDSA",
        _ => false,
    }
}

fn nonempty(key: &Map<String, Value>, name: &str) -> bool {
    string(key, name).is_some_and(|value| !value.is_empty())
}

fn string<'a>(key: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    key.get(name).and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_only_public_supported_private_key_jwt_material() {
        assert!(validate_public_jwks(&json!({
            "keys": [{"kty": "RSA", "n": "n", "e": "AQAB", "alg": "PS256"}]
        })));
        assert!(validate_public_jwks(&json!({
            "keys": [{"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}]
        })));
        assert!(validate_public_jwks(&json!({
            "keys": [{"kty": "OKP", "crv": "Ed25519", "x": "x", "alg": "EdDSA"}]
        })));
        for invalid in [
            json!([]),
            json!({"keys": []}),
            json!({"keys": [{"kty": "oct", "k": "secret"}]}),
            json!({"keys": [{"kty": "RSA", "n": "n", "e": "e", "d": "private"}]}),
            json!({"keys": [{"kty": "EC", "crv": "secp256k1", "x": "x", "y": "y"}]}),
            json!({"keys": [{"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "ES384"}]}),
        ] {
            assert!(!validate_public_jwks(&invalid));
        }
    }
}
