use super::{OAuthProviderConfig, OAuthTokens, OAuthUserInfo, OidcConfig};
use crate::AuthError;
use chrono::{Duration, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) fn parse_token_response(value: Value) -> Result<OAuthTokens, AuthError> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or(AuthError::OAuthInvalidCode)?;
    let access_token = take_string(&mut object, "access_token");
    let refresh_token = take_string(&mut object, "refresh_token");
    let id_token = take_string(&mut object, "id_token");
    if access_token.is_none() && id_token.is_none() {
        return Err(AuthError::OAuthInvalidCode);
    }
    let access_token_expires_at =
        take_i64(&mut object, "expires_in").map(|seconds| Utc::now() + Duration::seconds(seconds));
    let refresh_token_expires_at = take_i64(&mut object, "refresh_token_expires_in")
        .map(|seconds| Utc::now() + Duration::seconds(seconds));
    let scopes = take_string(&mut object, "scope")
        .map(|scope| {
            scope
                .split([' ', ','])
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(OAuthTokens {
        access_token,
        refresh_token,
        id_token,
        access_token_expires_at,
        refresh_token_expires_at,
        scopes,
        extra: object,
    })
}

fn take_string(object: &mut serde_json::Map<String, Value>, key: &str) -> Option<String> {
    object.remove(key).and_then(|value| match value {
        Value::String(value) => Some(value),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    })
}

fn take_i64(object: &mut serde_json::Map<String, Value>, key: &str) -> Option<i64> {
    object.remove(key).and_then(|value| value.as_i64())
}

pub(super) async fn verify_id_token(
    token: &str,
    oidc: &OidcConfig,
    expected_nonce: Option<&str>,
) -> Result<Value, AuthError> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| AuthError::OAuthInvalidToken)?;
    if !oidc.algorithms.contains(&header.alg) {
        return Err(AuthError::OAuthInvalidToken);
    }
    let response = reqwest::get(&oidc.jwks_url)
        .await
        .map_err(|_| AuthError::OAuthInvalidToken)?;
    if !response.status().is_success() {
        return Err(AuthError::OAuthInvalidToken);
    }
    let jwks: jsonwebtoken::jwk::JwkSet = response
        .json()
        .await
        .map_err(|_| AuthError::OAuthInvalidToken)?;
    let jwk = header
        .kid
        .as_deref()
        .and_then(|kid| jwks.find(kid))
        .ok_or(AuthError::OAuthInvalidToken)?;
    let key = jsonwebtoken::DecodingKey::from_jwk(jwk).map_err(|_| AuthError::OAuthInvalidToken)?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_audience(&oidc.audiences);
    if !oidc.issuers.is_empty() {
        validation.set_issuer(&oidc.issuers);
    }
    validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
    let claims = jsonwebtoken::decode::<Value>(token, &key, &validation)
        .map_err(|_| AuthError::OAuthInvalidToken)?
        .claims;
    validate_dynamic_issuer(&claims, oidc)?;
    let issued_at = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(AuthError::OAuthInvalidToken)?;
    if Utc::now().timestamp() - issued_at > oidc.maximum_age.num_seconds() {
        return Err(AuthError::OAuthInvalidToken);
    }
    validate_nonce(&claims, oidc, expected_nonce)?;
    Ok(claims)
}

fn validate_dynamic_issuer(claims: &Value, oidc: &OidcConfig) -> Result<(), AuthError> {
    if let Some(template) = &oidc.dynamic_issuer_template {
        let tenant = claims
            .get("tid")
            .and_then(Value::as_str)
            .ok_or(AuthError::OAuthInvalidToken)?;
        let expected = template.replace("{tid}", tenant);
        if claims.get("iss").and_then(Value::as_str) != Some(expected.as_str()) {
            return Err(AuthError::OAuthInvalidToken);
        }
    }
    Ok(())
}

fn validate_nonce(
    claims: &Value,
    oidc: &OidcConfig,
    expected: Option<&str>,
) -> Result<(), AuthError> {
    if !oidc.requires_nonce {
        return Ok(());
    }
    let expected = expected.ok_or(AuthError::OAuthNonceBindingMissing)?;
    let actual = claims.get("nonce").and_then(Value::as_str);
    let hashed = hex::encode(Sha256::digest(expected.as_bytes()));
    if actual != Some(expected) && !(oidc.nonce_sha256_fallback && actual == Some(hashed.as_str()))
    {
        return Err(AuthError::OAuthInvalidToken);
    }
    Ok(())
}

pub(crate) fn map_profile(
    config: &OAuthProviderConfig,
    profile: Value,
) -> Result<OAuthUserInfo, AuthError> {
    let mapped = config
        .profile
        .profile_root
        .as_deref()
        .and_then(|pointer| profile.pointer(pointer))
        .unwrap_or(&profile);
    let account_id = first_text(mapped, &config.profile.subject)
        .filter(|value| !matches!(value.as_str(), "" | "null" | "undefined"))
        .ok_or(AuthError::OAuthUserInfoUnavailable)?;
    let email = first_text(mapped, &config.profile.email)
        .or_else(|| {
            config
                .profile
                .synthetic_email_domain
                .as_ref()
                .map(|domain| format!("{account_id}@{domain}"))
        })
        .ok_or(AuthError::OAuthEmailNotFound)?
        .to_lowercase();
    let name = mapped_name(config, mapped);
    let image = first_text(mapped, &config.profile.image);
    let email_verified = mapped_email_verified(config, mapped);
    let profile = profile
        .as_object()
        .cloned()
        .ok_or(AuthError::OAuthUserInfoUnavailable)?;
    Ok(OAuthUserInfo {
        account_id,
        issuer: first_text(mapped, &config.profile.issuer)
            .or_else(|| config.issuer.clone())
            .unwrap_or_else(|| super::synthetic_issuer(&config.id)),
        name,
        email,
        email_verified,
        image,
        profile,
    })
}

fn mapped_name(config: &OAuthProviderConfig, value: &Value) -> String {
    if config.profile.join_name_fields {
        config
            .profile
            .name
            .iter()
            .filter_map(|pointer| first_text(value, std::slice::from_ref(pointer)))
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        first_text(value, &config.profile.name).unwrap_or_default()
    }
}

fn mapped_email_verified(config: &OAuthProviderConfig, value: &Value) -> bool {
    if config.profile.require_all_email_verified_fields {
        !config.profile.email_verified.is_empty()
            && config
                .profile
                .email_verified
                .iter()
                .all(|pointer| first_bool(value, std::slice::from_ref(pointer)) == Some(true))
    } else {
        first_bool(value, &config.profile.email_verified).unwrap_or(false)
    }
}

fn first_text(value: &Value, pointers: &[String]) -> Option<String> {
    pointers.iter().find_map(|pointer| {
        value.pointer(pointer).and_then(|value| match value {
            Value::String(value) if !value.trim().is_empty() => Some(value.clone()),
            Value::Number(value) => Some(value.to_string()),
            _ => None,
        })
    })
}

fn first_bool(value: &Value, pointers: &[String]) -> Option<bool> {
    pointers.iter().find_map(|pointer| {
        value.pointer(pointer).and_then(|value| match value {
            Value::Bool(value) => Some(*value),
            Value::Number(value) => value.as_i64().map(|value| value != 0),
            Value::String(value) if value == "true" => Some(true),
            Value::String(value) if value == "false" => Some(false),
            _ => None,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::get};
    use serde_json::json;

    async fn jwks() -> Json<Value> {
        Json(
            json!({"keys":[{"kty":"oct","kid":"fixture","alg":"HS256","k":"c3VwZXItc2VjcmV0LXNpZ25pbmcta2V5"}]}),
        )
    }

    async fn oidc_fixture() -> (OidcConfig, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/jwks", get(jwks)))
                .await
                .unwrap();
        });
        (
            OidcConfig {
                jwks_url: format!("http://{address}/jwks"),
                issuers: vec!["https://issuer.fixture".into()],
                audiences: vec!["fixture-client".into()],
                algorithms: vec![jsonwebtoken::Algorithm::HS256],
                requires_nonce: true,
                nonce_sha256_fallback: false,
                maximum_age: Duration::hours(1),
                dynamic_issuer_template: None,
            },
            server,
        )
    }

    fn id_token(overrides: Value, key: &[u8]) -> String {
        let now = Utc::now().timestamp();
        let mut claims = json!({"sub":"subject-123","iss":"https://issuer.fixture","aud":"fixture-client","iat":now,"exp":now+3600,"nonce":"bound-nonce","email":"casey@example.com"});
        claims
            .as_object_mut()
            .unwrap()
            .extend(overrides.as_object().cloned().unwrap_or_default());
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("fixture".into());
        jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(key),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn id_tokens_are_bound_to_signature_issuer_audience_age_and_nonce() {
        let (oidc, server) = oidc_fixture().await;
        let valid = id_token(json!({}), b"super-secret-signing-key");
        assert!(
            verify_id_token(&valid, &oidc, Some("bound-nonce"))
                .await
                .is_ok()
        );
        assert!(matches!(
            verify_id_token(&valid, &oidc, Some("wrong-nonce")).await,
            Err(AuthError::OAuthInvalidToken)
        ));
        for claims in [
            json!({"iss":"https://evil.example"}),
            json!({"aud":"other-client"}),
            json!({"iat":Utc::now().timestamp()-7200}),
        ] {
            assert!(matches!(
                verify_id_token(
                    &id_token(claims, b"super-secret-signing-key"),
                    &oidc,
                    Some("bound-nonce")
                )
                .await,
                Err(AuthError::OAuthInvalidToken)
            ));
        }
        let forged = id_token(json!({}), b"attacker-key");
        assert!(matches!(
            verify_id_token(&forged, &oidc, Some("bound-nonce")).await,
            Err(AuthError::OAuthInvalidToken)
        ));
        server.abort();
    }
}
