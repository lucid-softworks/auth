use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::AgentJwtError;

pub(crate) fn jwk_thumbprint(jwk: &Value) -> Result<String, AgentJwtError> {
    let field = |name: &'static str| {
        jwk.get(name)
            .and_then(Value::as_str)
            .ok_or(AgentJwtError::InvalidPublicKey)
    };
    let canonical = match field("kty")? {
        "RSA" => format!(
            r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
            field("e")?,
            field("n")?
        ),
        "EC" => format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
            field("crv")?,
            field("x")?,
            field("y")?
        ),
        "OKP" => format!(
            r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
            field("crv")?,
            field("x")?
        ),
        _ => return Err(AgentJwtError::InvalidPublicKey),
    };
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rfc_7638_thumbprint_ignores_optional_jwk_members() {
        let plain = json!({"kty":"OKP","crv":"Ed25519","x":"public"});
        let decorated =
            json!({"kid":"ignored","alg":"EdDSA","x":"public","crv":"Ed25519","kty":"OKP"});
        let expected = "nT1AHQ8OqEGnK4wrHm6iCEHO-DmJ9Q9aPsaYmo7IViM";
        assert_eq!(jwk_thumbprint(&plain).unwrap(), expected);
        assert_eq!(jwk_thumbprint(&decorated).unwrap(), expected);
    }
}
