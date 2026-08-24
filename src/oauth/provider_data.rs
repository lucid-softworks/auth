use super::{OAuthProviderConfig, OAuthTokens, OAuthUserInfo};
use crate::AuthError;
use chrono::{Duration, Utc};
use serde_json::Value;

pub(crate) fn parse_token_response(value: Value) -> Result<OAuthTokens, AuthError> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or(AuthError::OAuthInvalidCode)?;
    let raw = object.clone();
    let access_token = take_string(&mut object, "access_token");
    let refresh_token = take_string(&mut object, "refresh_token");
    let id_token = take_string(&mut object, "id_token");
    let access_token_expires_at = take_i64(&mut object, "expires_in")
        .filter(|seconds| *seconds != 0)
        .map(|seconds| Utc::now() + Duration::seconds(seconds));
    let refresh_token_expires_at = take_i64(&mut object, "refresh_token_expires_in")
        .filter(|seconds| *seconds != 0)
        .map(|seconds| Utc::now() + Duration::seconds(seconds));
    let scopes = object.remove("scope").map(parse_scopes).unwrap_or_default();
    Ok(OAuthTokens {
        access_token,
        refresh_token,
        id_token,
        access_token_expires_at,
        refresh_token_expires_at,
        scopes,
        extra: raw,
    })
}

fn parse_scopes(value: Value) -> Vec<String> {
    match value {
        Value::String(value) => value
            .split_whitespace()
            .filter(|scope| !scope.is_empty())
            .map(str::to_owned)
            .collect(),
        Value::Array(values) => values
            .into_iter()
            .filter_map(|value| value.as_str().map(str::trim).map(str::to_owned))
            .filter(|scope| !scope.is_empty())
            .collect(),
        _ => Vec::new(),
    }
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
        additional_fields: serde_json::Map::new(),
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
    use crate::oauth::{OidcConfig, verify_id_token};
    use axum::{Json, Router, routing::get};
    use serde_json::json;

    async fn jwks() -> Json<Value> {
        Json(
            json!({"keys":[{"kty":"oct","kid":"fixture","alg":"HS256","k":"c3VwZXItc2VjcmV0LXNpZ25pbmcta2V5LTMyYnl0ZXMh"}]}),
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
                algorithms: vec!["HS256".into()],
                requires_nonce: true,
                nonce_sha256_fallback: false,
                maximum_age: Some(Duration::hours(1)),
                dynamic_issuer_template: None,
            },
            server,
        )
    }

    fn id_token(overrides: Value, key: &[u8]) -> String {
        id_token_with_kid(overrides, key, Some("fixture"))
    }

    fn id_token_with_kid(overrides: Value, key: &[u8], kid: Option<&str>) -> String {
        let now = Utc::now().timestamp();
        let mut claims = json!({"sub":"subject-123","iss":"https://issuer.fixture","aud":"fixture-client","iat":now,"exp":now+3600,"nonce":"bound-nonce","email":"casey@example.com"});
        claims
            .as_object_mut()
            .unwrap()
            .extend(overrides.as_object().cloned().unwrap_or_default());
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = kid.map(str::to_owned);
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
        let valid = id_token(json!({}), b"super-secret-signing-key-32bytes!");
        assert!(
            verify_id_token(&valid, &oidc, Some("bound-nonce"))
                .await
                .is_ok()
        );
        assert!(verify_id_token(&valid, &oidc, None).await.is_ok());
        let mut nonce_disabled = oidc.clone();
        nonce_disabled.requires_nonce = false;
        assert!(matches!(
            verify_id_token(&valid, &nonce_disabled, Some("wrong-nonce")).await,
            Err(AuthError::OAuthInvalidToken)
        ));
        let no_kid = id_token_with_kid(json!({}), b"super-secret-signing-key-32bytes!", None);
        assert!(
            verify_id_token(&no_kid, &oidc, Some("bound-nonce"))
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
                    &id_token(claims, b"super-secret-signing-key-32bytes!"),
                    &oidc,
                    Some("bound-nonce")
                )
                .await,
                Err(AuthError::OAuthInvalidToken)
            ));
        }
        let forged = id_token(json!({}), b"attacker-key-with-at-least-32-bytes");
        assert!(matches!(
            verify_id_token(&forged, &oidc, Some("bound-nonce")).await,
            Err(AuthError::OAuthInvalidToken)
        ));
        server.abort();
    }
}
