use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use josekit::jwk::Jwk;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use super::{
    McpDpopOptions, McpDpopReplayReservation, McpDpopReplayStore, McpProtectedRequest,
    VerificationFailure,
};

mod signature;

pub(super) struct AccessTokenAuthorization {
    pub(super) scheme: AuthorizationScheme,
    pub(super) token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthorizationScheme {
    Bearer,
    Dpop,
}

pub(super) fn parse_authorization(
    value: Option<&str>,
) -> Result<AccessTokenAuthorization, VerificationFailure> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Err(invalid_token("missing authorization header"));
    };
    let Some(separator) = value.find(char::is_whitespace) else {
        return Err(invalid_token("authorization scheme must be Bearer or DPoP"));
    };
    let scheme = &value[..separator];
    let token = value[separator..].trim();
    if token.is_empty() {
        return Err(invalid_token("missing authorization header"));
    }
    let scheme = if scheme.eq_ignore_ascii_case("bearer") {
        AuthorizationScheme::Bearer
    } else if scheme.eq_ignore_ascii_case("dpop") {
        AuthorizationScheme::Dpop
    } else {
        return Err(invalid_token("authorization scheme must be Bearer or DPoP"));
    };
    Ok(AccessTokenAuthorization {
        scheme,
        token: token.into(),
    })
}

pub(super) async fn enforce_binding(
    payload: &Map<String, Value>,
    authorization: &AccessTokenAuthorization,
    request: &McpProtectedRequest,
    options: &McpDpopOptions,
    replay_store: &dyn McpDpopReplayStore,
) -> Result<(), VerificationFailure> {
    let expected_jkt = confirmation_jkt(payload.get("cnf"));
    let Some(expected_jkt) = expected_jkt else {
        if authorization.scheme == AuthorizationScheme::Dpop {
            return Err(invalid_token(
                "DPoP authorization requires a DPoP-bound access token",
            ));
        }
        return Ok(());
    };
    if authorization.scheme != AuthorizationScheme::Dpop {
        return Err(invalid_token(
            "DPoP-bound access token requires the DPoP authorization scheme",
        ));
    }
    let proof = request
        .dpop_proof_jwt
        .as_deref()
        .ok_or_else(|| invalid_dpop("DPoP proof header is required"))?;
    verify_proof(
        proof,
        &request.method,
        &request.url,
        &authorization.token,
        expected_jkt,
        options,
        replay_store,
    )
    .await
}

async fn verify_proof(
    proof: &str,
    method: &str,
    request_url: &str,
    access_token: &str,
    expected_jkt: &str,
    options: &McpDpopOptions,
    replay_store: &dyn McpDpopReplayStore,
) -> Result<(), VerificationFailure> {
    let material = decode_proof(proof, options)?;
    let claims = validate_proof_claims(
        &material.claims,
        method,
        request_url,
        access_token,
        options.proof_max_age_seconds,
    )?;
    let jkt = jwk_thumbprint(&material.public_jwk)?;
    if jkt != expected_jkt {
        return Err(invalid_dpop(
            "DPoP proof key does not match the bound token",
        ));
    }
    reserve_proof(replay_store, &jkt, &claims, options.proof_max_age_seconds).await
}

struct DecodedProof {
    claims: Map<String, Value>,
    public_jwk: Map<String, Value>,
}

fn decode_proof(
    proof: &str,
    options: &McpDpopOptions,
) -> Result<DecodedProof, VerificationFailure> {
    if proof.split('.').count() != 3 {
        return Err(invalid_dpop("DPoP proof must be a compact JWT"));
    }
    let header = decode_part(proof.split('.').next().unwrap_or_default())
        .ok_or_else(|| invalid_dpop("DPoP proof header is invalid"))?;
    if header.get("typ").and_then(Value::as_str) != Some("dpop+jwt") {
        return Err(invalid_dpop("DPoP proof typ must be \"dpop+jwt\""));
    }
    let algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if algorithm.is_empty() || algorithm == "none" || algorithm.starts_with("HS") {
        return Err(invalid_dpop(
            "DPoP proof must use an asymmetric JWS algorithm",
        ));
    }
    let allowed = options
        .signing_algorithms
        .as_ref()
        .map(|configured| configured.iter().any(|allowed| allowed == algorithm))
        .unwrap_or_else(|| crate::oauth_provider::DEFAULT_DPOP_ALGORITHMS.contains(&algorithm));
    if !allowed {
        return Err(invalid_dpop("DPoP proof uses an unsupported JWS algorithm"));
    }
    let public_jwk = header
        .get("jwk")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_dpop("DPoP proof header must include a public jwk"))?;
    if public_jwk.get("kty").and_then(Value::as_str) == Some("oct") {
        return Err(invalid_dpop("DPoP proof jwk must be asymmetric"));
    }
    for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        if public_jwk.contains_key(field) {
            return Err(invalid_dpop(
                "DPoP proof jwk must not contain private key material",
            ));
        }
    }
    let jwk = Jwk::from_bytes(&serde_json::to_vec(public_jwk).map_err(infrastructure)?)
        .map_err(|error| invalid_dpop(&error.to_string()))?;
    let claims = signature::verify(proof, algorithm, &jwk)?;
    Ok(DecodedProof {
        claims,
        public_jwk: public_jwk.clone(),
    })
}

struct ValidatedProofClaims {
    htm: String,
    jti: String,
    iat: f64,
    normalized_request: String,
}

fn validate_proof_claims(
    claims: &Map<String, Value>,
    method: &str,
    request_url: &str,
    access_token: &str,
    proof_max_age_seconds: f64,
) -> Result<ValidatedProofClaims, VerificationFailure> {
    let htm = string_claim(claims, "htm")?;
    let htu = string_claim(claims, "htu")?;
    let jti = string_claim(claims, "jti")?;
    let iat = number_claim(claims, "iat")?;
    if jti.encode_utf16().count() > 512 {
        return Err(invalid_dpop("DPoP proof jti is too large"));
    }
    if !htm.eq_ignore_ascii_case(method) {
        return Err(invalid_dpop(
            "DPoP proof htm does not match the request method",
        ));
    }
    let normalized_request = normalize_htu(request_url)?;
    if normalize_htu(htu)? != normalized_request {
        return Err(invalid_dpop(
            "DPoP proof htu does not match the request URL",
        ));
    }
    let now = Utc::now().timestamp_millis() as f64 / 1_000.0;
    if iat > now.floor() + 5.0 || now.floor() - iat > proof_max_age_seconds {
        return Err(invalid_dpop(
            "DPoP proof iat is outside the accepted window",
        ));
    }
    let ath = claims
        .get("ath")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_dpop("DPoP proof must include an ath claim"))?;
    if ath != sha256_url(access_token.as_bytes()) {
        return Err(invalid_dpop(
            "DPoP proof ath does not match the access token",
        ));
    }
    Ok(ValidatedProofClaims {
        htm: htm.into(),
        jti: jti.into(),
        iat,
        normalized_request,
    })
}

async fn reserve_proof(
    replay_store: &dyn McpDpopReplayStore,
    jkt: &str,
    claims: &ValidatedProofClaims,
    proof_max_age_seconds: f64,
) -> Result<(), VerificationFailure> {
    let replay_key = sha256_url(
        format!(
            "{}\n{}\n{}\n{}",
            jkt,
            claims.htm.to_ascii_uppercase(),
            claims.normalized_request,
            claims.jti
        )
        .as_bytes(),
    );
    let expires_at_millis = ((claims.iat + proof_max_age_seconds) * 1_000.0) as i64;
    let expires_at = DateTime::from_timestamp_millis(expires_at_millis)
        .ok_or_else(|| invalid_dpop("DPoP proof iat is outside the accepted window"))?;
    let reserved = replay_store
        .reserve(McpDpopReplayReservation {
            key: replay_key,
            expires_at,
            now: Utc::now(),
        })
        .await
        .map_err(|error| VerificationFailure::Infrastructure(error.to_string()))?;
    if !reserved {
        return Err(invalid_dpop("DPoP proof jti has already been used"));
    }
    Ok(())
}

fn string_claim<'a>(
    claims: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a str, VerificationFailure> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_dpop("DPoP proof must include htm, htu, jti, and iat claims"))
}

fn number_claim(claims: &Map<String, Value>, name: &str) -> Result<f64, VerificationFailure> {
    claims
        .get(name)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .ok_or_else(|| invalid_dpop("DPoP proof must include htm, htu, jti, and iat claims"))
}

fn normalize_htu(value: &str) -> Result<String, VerificationFailure> {
    let url = url::Url::parse(value).map_err(|_| invalid_dpop("DPoP proof htu is invalid"))?;
    if url.fragment().is_some_and(|fragment| !fragment.is_empty()) {
        return Err(invalid_dpop("DPoP proof htu must not contain a fragment"));
    }
    Ok(format!(
        "{}{}",
        url.origin().ascii_serialization(),
        url.path()
    ))
}

fn confirmation_jkt(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_object)
        .and_then(|confirmation| confirmation.get("jkt"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn jwk_thumbprint(jwk: &Map<String, Value>) -> Result<String, VerificationFailure> {
    let field = |name: &str| {
        jwk.get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_dpop("DPoP proof header must include a public jwk"))
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
        _ => return Err(invalid_dpop("DPoP proof jwk must be asymmetric")),
    };
    Ok(sha256_url(canonical.as_bytes()))
}

fn decode_part(value: &str) -> Option<Value> {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(value).ok()?).ok()
}

fn sha256_url(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value))
}

fn invalid_token(message: &str) -> VerificationFailure {
    VerificationFailure::Challenge(crate::OAuthProviderError::InvalidToken(message.into()))
}

fn invalid_dpop(message: &str) -> VerificationFailure {
    VerificationFailure::Challenge(crate::OAuthProviderError::InvalidDpopProof(message.into()))
}

fn infrastructure(error: serde_json::Error) -> VerificationFailure {
    VerificationFailure::Infrastructure(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_bearer_and_dpop_schemes() {
        assert_eq!(
            parse_authorization(Some("bearer token")).unwrap().scheme,
            AuthorizationScheme::Bearer
        );
        assert_eq!(
            parse_authorization(Some("DPoP token")).unwrap().scheme,
            AuthorizationScheme::Dpop
        );
        assert!(parse_authorization(None).is_err());
        assert!(parse_authorization(Some("Basic token")).is_err());
    }

    #[test]
    fn htu_normalization_discards_query_but_rejects_fragment() {
        assert_eq!(
            normalize_htu("https://api.example.test/mcp?tenant=a").unwrap(),
            "https://api.example.test/mcp"
        );
        assert!(normalize_htu("https://api.example.test/mcp#bad").is_err());
    }
}
