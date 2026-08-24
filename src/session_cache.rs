use crate::{AuthError, CookieCacheStrategy};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SessionCachePayload {
    pub session: Value,
    pub user: Value,
    pub updated_at: i64,
    #[serde(default = "default_version")]
    pub version: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompactCache {
    session: SessionCachePayload,
    expires_at: i64,
    signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedCompact<'a> {
    session: &'a Value,
    user: &'a Value,
    updated_at: i64,
    version: &'a str,
    expires_at: i64,
}

#[derive(Serialize, Deserialize)]
struct JwtPayload {
    #[serde(flatten)]
    cache: SessionCachePayload,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
}

pub(crate) fn encode(
    payload: SessionCachePayload,
    strategy: CookieCacheStrategy,
    secret: &[u8],
    max_age_seconds: i64,
) -> Result<String, AuthError> {
    match strategy {
        CookieCacheStrategy::Compact => encode_compact(payload, secret, max_age_seconds),
        CookieCacheStrategy::Jwt => encode_jwt(payload, secret, max_age_seconds),
        CookieCacheStrategy::Jwe => encode_jwe(payload, secret, max_age_seconds),
    }
}

pub(crate) fn decode(
    value: &str,
    strategy: CookieCacheStrategy,
    secret: &[u8],
) -> Option<(SessionCachePayload, i64)> {
    match strategy {
        CookieCacheStrategy::Compact => decode_compact(value, secret),
        CookieCacheStrategy::Jwt => decode_jwt(value, secret),
        CookieCacheStrategy::Jwe => decode_jwe(value, secret),
    }
}

fn encode_compact(
    payload: SessionCachePayload,
    secret: &[u8],
    max_age_seconds: i64,
) -> Result<String, AuthError> {
    let expires_at = now_millis() + max_age_seconds.saturating_mul(1_000);
    let signature = sign(
        secret,
        serde_json::to_string(&SignedCompact {
            session: &payload.session,
            user: &payload.user,
            updated_at: payload.updated_at,
            version: &payload.version,
            expires_at,
        })?
        .as_bytes(),
    )?;
    let encoded = serde_json::to_vec(&CompactCache {
        session: payload,
        expires_at,
        signature,
    })?;
    Ok(URL_SAFE_NO_PAD.encode(encoded))
}

fn decode_compact(value: &str, secret: &[u8]) -> Option<(SessionCachePayload, i64)> {
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    let compact: CompactCache = serde_json::from_slice(&decoded).ok()?;
    verify(
        secret,
        serde_json::to_string(&SignedCompact {
            session: &compact.session.session,
            user: &compact.session.user,
            updated_at: compact.session.updated_at,
            version: &compact.session.version,
            expires_at: compact.expires_at,
        })
        .ok()?
        .as_bytes(),
        &compact.signature,
    )?;
    Some((compact.session, compact.expires_at))
}

fn encode_jwt(
    payload: SessionCachePayload,
    secret: &[u8],
    max_age_seconds: i64,
) -> Result<String, AuthError> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
    let now = chrono::Utc::now().timestamp();
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&JwtPayload {
        cache: payload,
        iat: now,
        exp: now + max_age_seconds,
        jti: None,
    })?);
    let signing_input = format!("{header}.{body}");
    Ok(format!(
        "{signing_input}.{}",
        sign(secret, signing_input.as_bytes())?
    ))
}

fn decode_jwt(value: &str, secret: &[u8]) -> Option<(SessionCachePayload, i64)> {
    let mut parts = value.split('.');
    let header = parts.next()?;
    let body = parts.next()?;
    let signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let header_value: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    if header_value.get("alg")?.as_str()? != "HS256" {
        return None;
    }
    verify(secret, format!("{header}.{body}").as_bytes(), signature)?;
    let payload: JwtPayload = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).ok()?).ok()?;
    Some((payload.cache, payload.exp.saturating_mul(1_000)))
}

fn encode_jwe(
    payload: SessionCachePayload,
    secret: &[u8],
    max_age_seconds: i64,
) -> Result<String, AuthError> {
    crate::symmetric_jwe::encode(payload, secret, b"better-auth-session", max_age_seconds)
}

fn decode_jwe(value: &str, secret: &[u8]) -> Option<(SessionCachePayload, i64)> {
    crate::symmetric_jwe::decode(value, secret, b"better-auth-session")
}

fn sign(secret: &[u8], message: &[u8]) -> Result<String, AuthError> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| crypto_error("invalid cookie-cache signing key"))?;
    mac.update(message);
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn verify(secret: &[u8], message: &[u8], signature: &str) -> Option<()> {
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(message);
    mac.verify_slice(&signature).ok()
}

fn now_millis() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn default_version() -> String {
    "1".into()
}

fn crypto_error(message: &str) -> AuthError {
    AuthError::InvalidConfiguration(message.into())
}

impl From<serde_json::Error> for AuthError {
    fn from(error: serde_json::Error) -> Self {
        AuthError::Storage(format!("session cookie-cache JSON failed: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> SessionCachePayload {
        SessionCachePayload {
            session: serde_json::json!({
                "id": "018f0000-0000-7000-8000-000000000001",
                "token": "primary-token",
                "expiresAt": "2099-01-01T00:00:00Z"
            }),
            user: serde_json::json!({"id": "018f0000-0000-7000-8000-000000000002"}),
            updated_at: 1_700_000_000_000,
            version: "release-2".into(),
        }
    }

    #[test]
    fn every_better_auth_strategy_round_trips_and_rejects_tampering() {
        for strategy in [
            CookieCacheStrategy::Compact,
            CookieCacheStrategy::Jwt,
            CookieCacheStrategy::Jwe,
        ] {
            let encoded = encode(payload(), strategy, &[82; 32], 300).unwrap();
            let (decoded, expires_at) = decode(&encoded, strategy, &[82; 32]).unwrap();
            assert_eq!(decoded.version, "release-2");
            assert_eq!(decoded.session["token"], "primary-token");
            assert!(expires_at > now_millis());

            for other in [
                CookieCacheStrategy::Compact,
                CookieCacheStrategy::Jwt,
                CookieCacheStrategy::Jwe,
            ] {
                if other != strategy {
                    assert!(decode(&encoded, other, &[82; 32]).is_none());
                }
            }

            let mut tampered = encoded.into_bytes();
            let last = tampered.len() - 1;
            tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
            assert!(decode(std::str::from_utf8(&tampered).unwrap(), strategy, &[82; 32]).is_none());
        }
    }

    #[test]
    fn jwt_and_jwe_headers_match_better_auth_algorithms() {
        let jwt = encode(payload(), CookieCacheStrategy::Jwt, &[82; 32], 300).unwrap();
        let jwt_header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(jwt.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(jwt_header, serde_json::json!({"alg": "HS256"}));

        let jwe = encode(payload(), CookieCacheStrategy::Jwe, &[82; 32], 300).unwrap();
        let jwe_header: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(jwe.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(jwe_header["alg"], "dir");
        assert_eq!(jwe_header["enc"], "A256CBC-HS512");
        assert!(
            jwe_header["kid"]
                .as_str()
                .is_some_and(|kid| !kid.is_empty())
        );
    }
}
