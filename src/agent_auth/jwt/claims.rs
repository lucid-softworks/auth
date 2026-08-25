use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{AgentJwtError, AgentJwtVerifyOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AgentJwtKind {
    Host,
    Agent,
}

impl AgentJwtKind {
    fn token_type(self) -> &'static str {
        match self {
            Self::Host => "host+jwt",
            Self::Agent => "agent+jwt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentJwtHeader {
    pub typ: String,
    pub alg: String,
    pub kid: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AgentJwtClaims {
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub audience: Vec<String>,
    pub jti: Option<String>,
    pub issued_at: Option<f64>,
    pub not_before: Option<f64>,
    pub expires_at: Option<f64>,
    pub capabilities: Vec<String>,
    pub capabilities_present: bool,
    pub htm: Option<String>,
    pub htu: Option<String>,
    pub ath: Option<String>,
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AgentBoundRequest<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub serialized_body: Option<&'a str>,
}

pub(crate) fn decode_agent_jwt(token: &str) -> Result<super::VerifiedAgentJwt, AgentJwtError> {
    let mut segments = token.split('.');
    let header = decode_object(segments.next())?;
    let claims = decode_object(segments.next())?;
    if segments.next().is_none() || segments.next().is_some() {
        return Err(AgentJwtError::Malformed);
    }
    let header = AgentJwtHeader {
        typ: string(&header, "typ")?.to_owned(),
        alg: string(&header, "alg")?.to_owned(),
        kid: optional_string(&header, "kid")?,
    };
    let capabilities_present = claims.get("capabilities").is_some_and(Value::is_array);
    let decoded = AgentJwtClaims {
        issuer: optional_string(&claims, "iss")?,
        subject: optional_string(&claims, "sub")?,
        audience: audience(&claims)?,
        jti: optional_string(&claims, "jti")?,
        issued_at: optional_number(&claims, "iat")?,
        not_before: optional_number(&claims, "nbf")?,
        expires_at: optional_number(&claims, "exp")?,
        capabilities: string_array(&claims, "capabilities")?,
        capabilities_present,
        htm: optional_string(&claims, "htm")?,
        htu: optional_string(&claims, "htu")?,
        ath: optional_string(&claims, "ath")?,
        extra: claims,
    };
    Ok(super::VerifiedAgentJwt {
        header,
        claims: decoded,
    })
}

pub(super) fn validate_unverified(
    decoded: &super::VerifiedAgentJwt,
    options: &AgentJwtVerifyOptions<'_>,
) -> Result<(), AgentJwtError> {
    if decoded.header.typ != options.kind.token_type() {
        return Err(AgentJwtError::UnexpectedType);
    }
    if options.require_audience && decoded.claims.audience.is_empty() {
        return Err(AgentJwtError::MissingClaim("aud"));
    }
    if !decoded.claims.audience.is_empty() && !options.audience.matches(&decoded.claims.audience)? {
        return Err(AgentJwtError::InvalidAudience);
    }
    match options.kind {
        AgentJwtKind::Host if decoded.claims.issuer.is_none() => {
            return Err(AgentJwtError::MissingClaim("iss"));
        }
        AgentJwtKind::Agent if decoded.claims.subject.is_none() => {
            return Err(AgentJwtError::MissingClaim("sub"));
        }
        _ => {}
    }
    if let Some(expected) = options.expected_issuer
        && decoded
            .claims
            .issuer
            .as_deref()
            .is_some_and(|issuer| issuer != expected)
    {
        return Err(AgentJwtError::InvalidClaim("iss"));
    }
    if !options.skip_replay_check
        && options.replay_partition.is_some()
        && decoded.claims.jti.as_deref().is_none_or(str::is_empty)
    {
        return Err(AgentJwtError::MissingClaim("jti"));
    }
    Ok(())
}

pub(super) fn validate_times(
    claims: &AgentJwtClaims,
    max_age: Duration,
    now: DateTime<Utc>,
) -> Result<(), AgentJwtError> {
    let now = now.timestamp() as f64;
    let issued_at = claims.issued_at.ok_or(AgentJwtError::MissingClaim("iat"))?;
    if issued_at > now {
        return Err(AgentJwtError::IssuedInFuture);
    }
    if claims.not_before.is_some_and(|not_before| not_before > now) {
        return Err(AgentJwtError::InvalidClaim("nbf"));
    }
    if now - issued_at > max_age.as_secs_f64() {
        return Err(AgentJwtError::TooOld);
    }
    if claims
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Err(AgentJwtError::Expired);
    }
    Ok(())
}

pub(super) fn validate_request_binding(
    claims: &AgentJwtClaims,
    request: &AgentBoundRequest<'_>,
) -> Result<(), AgentJwtError> {
    if claims.htm.is_none() && claims.htu.is_none() && claims.ath.is_none() {
        return Ok(());
    }
    if claims
        .htm
        .as_deref()
        .is_some_and(|method| !method.eq_ignore_ascii_case(request.method))
    {
        return Err(AgentJwtError::RequestBindingMismatch);
    }
    if let Some(expected) = claims.htu.as_deref() {
        let parsed =
            url::Url::parse(request.url).map_err(|_| AgentJwtError::RequestBindingMismatch)?;
        let actual = format!("{}{}", parsed.origin().ascii_serialization(), parsed.path());
        if expected != actual {
            return Err(AgentJwtError::RequestBindingMismatch);
        }
    }
    if let (Some(expected), Some(body)) = (claims.ath.as_deref(), request.serialized_body) {
        let actual = URL_SAFE_NO_PAD.encode(Sha256::digest(body.as_bytes()));
        if expected != actual {
            return Err(AgentJwtError::RequestBindingMismatch);
        }
    }
    Ok(())
}

fn decode_object(segment: Option<&str>) -> Result<Map<String, Value>, AgentJwtError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(segment.ok_or(AgentJwtError::Malformed)?)
        .map_err(|_| AgentJwtError::Malformed)?;
    serde_json::from_slice::<Value>(&decoded)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or(AgentJwtError::Malformed)
}

fn string<'a>(
    values: &'a Map<String, Value>,
    name: &'static str,
) -> Result<&'a str, AgentJwtError> {
    values
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(AgentJwtError::MissingClaim(name))
}

fn optional_string(
    values: &Map<String, Value>,
    name: &'static str,
) -> Result<Option<String>, AgentJwtError> {
    match values.get(name) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(AgentJwtError::InvalidClaim(name)),
    }
}

fn optional_number(
    values: &Map<String, Value>,
    name: &'static str,
) -> Result<Option<f64>, AgentJwtError> {
    match values.get(name) {
        None => Ok(None),
        Some(Value::Number(value)) => value
            .as_f64()
            .filter(|value| value.is_finite())
            .map(Some)
            .ok_or(AgentJwtError::InvalidClaim(name)),
        Some(_) => Err(AgentJwtError::InvalidClaim(name)),
    }
}

fn audience(values: &Map<String, Value>) -> Result<Vec<String>, AgentJwtError> {
    match values.get("aud") {
        None => Ok(Vec::new()),
        Some(Value::String(value)) => Ok(vec![value.clone()]),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(AgentJwtError::InvalidClaim("aud"))
            })
            .collect(),
        Some(_) => Err(AgentJwtError::InvalidClaim("aud")),
    }
}

fn string_array(
    values: &Map<String, Value>,
    name: &'static str,
) -> Result<Vec<String>, AgentJwtError> {
    match values.get(name) {
        None => Ok(Vec::new()),
        Some(Value::Array(values)) => Ok(values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()),
        Some(_) => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn encoded(value: Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
    }

    #[test]
    fn decoding_preserves_claims_and_filters_non_string_capabilities() {
        let token = format!(
            "{}.{}.signature",
            encoded(json!({"alg":"EdDSA","typ":"agent+jwt","kid":"key"})),
            encoded(json!({
                "sub":"agent", "aud":["one","two"], "jti":"id", "iat":10,
                "capabilities":["mail.send", 4], "custom":true
            }))
        );
        let decoded = decode_agent_jwt(&token).unwrap();
        assert_eq!(decoded.header.kid.as_deref(), Some("key"));
        assert_eq!(decoded.claims.audience, ["one", "two"]);
        assert_eq!(decoded.claims.capabilities, ["mail.send"]);
        assert_eq!(decoded.claims.extra["custom"], true);
    }

    #[test]
    fn validates_method_url_and_exact_serialized_body_bindings() {
        let body = r#"{"message":"hello"}"#;
        let claims = AgentJwtClaims {
            issuer: None,
            subject: Some("agent".into()),
            audience: vec!["https://example.test".into()],
            jti: Some("jti".into()),
            issued_at: Some(1.0),
            not_before: None,
            expires_at: None,
            capabilities: Vec::new(),
            capabilities_present: false,
            htm: Some("post".into()),
            htu: Some("https://example.test/action".into()),
            ath: Some(URL_SAFE_NO_PAD.encode(Sha256::digest(body.as_bytes()))),
            extra: Map::new(),
        };
        let request = AgentBoundRequest {
            method: "POST",
            url: "https://example.test/action?ignored=yes",
            serialized_body: Some(body),
        };
        assert!(validate_request_binding(&claims, &request).is_ok());
        assert!(matches!(
            validate_request_binding(
                &claims,
                &AgentBoundRequest {
                    method: "GET",
                    ..request
                }
            ),
            Err(AgentJwtError::RequestBindingMismatch)
        ));
    }

    #[test]
    fn max_age_requires_iat_and_exp_is_optional_but_enforced() {
        let now = DateTime::from_timestamp(100, 0).unwrap();
        let mut claims = AgentJwtClaims {
            issuer: None,
            subject: None,
            audience: Vec::new(),
            jti: None,
            issued_at: None,
            not_before: None,
            expires_at: None,
            capabilities: Vec::new(),
            capabilities_present: false,
            htm: None,
            htu: None,
            ath: None,
            extra: Map::new(),
        };
        assert!(matches!(
            validate_times(&claims, Duration::from_secs(60), now),
            Err(AgentJwtError::MissingClaim("iat"))
        ));
        claims.issued_at = Some(50.0);
        assert!(validate_times(&claims, Duration::from_secs(60), now).is_ok());
        claims.expires_at = Some(100.0);
        assert!(matches!(
            validate_times(&claims, Duration::from_secs(60), now),
            Err(AgentJwtError::Expired)
        ));
    }
}
