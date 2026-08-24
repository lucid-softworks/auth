use super::{
    provider::GenericOAuthProvider,
    types::{GenericOAuthAccountKeyContext, GenericOAuthMappedUser},
};
use crate::{AuthError, OAuthTokens, OAuthUserInfo};
use serde_json::Value;

pub(super) async fn get_user_info(
    provider: &GenericOAuthProvider,
    tokens: &OAuthTokens,
    expected_nonce: Option<&str>,
) -> Result<OAuthUserInfo, AuthError> {
    if let (Some(token), Some(oidc)) = (tokens.id_token.as_deref(), provider.oidc.as_ref()) {
        crate::oauth::verify_id_token(token, oidc, expected_nonce).await?;
    }
    let profile = raw_user_info(provider, tokens).await?;
    let mapped = if let Some(mapper) = &provider.config.map_profile_to_user {
        mapper.map_profile(&profile).await?
    } else {
        GenericOAuthMappedUser::default()
    };
    let mut user = serde_json::Map::from_iter([
        (
            "email".into(),
            profile.get("email").cloned().unwrap_or(Value::Null),
        ),
        (
            "emailVerified".into(),
            profile.get("emailVerified").cloned().unwrap_or(Value::Null),
        ),
        (
            "image".into(),
            profile.get("image").cloned().unwrap_or(Value::Null),
        ),
        (
            "name".into(),
            profile.get("name").cloned().unwrap_or(Value::Null),
        ),
    ]);
    user.extend(mapped);
    let email = text(user.get("email"))
        .filter(|email| !email.is_empty())
        .ok_or(AuthError::OAuthEmailNotFound)?;
    let (account_id, issuer) = account_key(provider, tokens, &profile).await?;
    let object = profile
        .as_object()
        .cloned()
        .ok_or(AuthError::OAuthUserInfoUnavailable)?;
    Ok(OAuthUserInfo {
        account_id,
        issuer,
        name: text(user.get("name")).unwrap_or_default(),
        email: email.to_lowercase(),
        email_verified: boolean(user.get("emailVerified")).unwrap_or(false),
        image: text(user.get("image")),
        additional_fields: user
            .into_iter()
            .filter(|(key, _)| {
                !matches!(key.as_str(), "email" | "emailVerified" | "image" | "name")
            })
            .collect(),
        profile: object,
    })
}

async fn raw_user_info(
    provider: &GenericOAuthProvider,
    tokens: &OAuthTokens,
) -> Result<Value, AuthError> {
    if let Some(callback) = &provider.config.get_user_info {
        return callback
            .user_info(tokens)
            .await?
            .ok_or(AuthError::OAuthUserInfoUnavailable);
    }
    if let Some(id_token) = tokens.id_token.as_deref()
        && let Ok(decoded) = jsonwebtoken::dangerous::insecure_decode::<Value>(id_token)
        && decoded.claims.get("sub").is_some_and(json_truthy)
        && decoded.claims.get("email").is_some_and(json_truthy)
    {
        return Ok(normalize_oidc_profile(decoded.claims));
    }
    let endpoint = provider
        .config
        .user_info_url
        .as_deref()
        .ok_or(AuthError::OAuthUserInfoUnavailable)?;
    let access_token = tokens
        .access_token
        .as_deref()
        .ok_or(AuthError::OAuthUserInfoUnavailable)?;
    let response = reqwest::Client::new()
        .get(endpoint)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| AuthError::OAuthUserInfoUnavailable)?;
    if !response.status().is_success() {
        return Err(AuthError::OAuthUserInfoUnavailable);
    }
    normalize_user_info(
        response
            .json::<Value>()
            .await
            .map_err(|_| AuthError::OAuthUserInfoUnavailable)?,
    )
}

async fn account_key(
    provider: &GenericOAuthProvider,
    tokens: &OAuthTokens,
    profile: &Value,
) -> Result<(String, String), AuthError> {
    let context = GenericOAuthAccountKeyContext {
        tokens: tokens.clone(),
        profile: profile.clone(),
    };
    let account_id = if let Some(resolver) = &provider.config.account_subject {
        resolver.account_subject(&context).await?
    } else {
        text(profile.get(if provider.is_oidc { "sub" } else { "id" })).unwrap_or_default()
    };
    validate_identity(&account_id)?;
    let issuer = if let Some(resolver) = &provider.config.account_issuer_resolver {
        resolver.account_issuer(&context).await?
    } else if let Some(issuer) = &provider.config.account_issuer {
        issuer.clone()
    } else if let Some(issuer) = &provider.issuer {
        issuer.clone()
    } else {
        crate::oauth::synthetic_issuer(&provider.config.provider_id)
    };
    validate_identity(&issuer)?;
    Ok((account_id, issuer))
}

fn normalize_oidc_profile(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        if let Some(subject) = object.get("sub").cloned() {
            object.entry("id").or_insert(subject);
        }
        if let Some(verified) = object.get("email_verified").cloned() {
            object.entry("emailVerified").or_insert(verified);
        }
        if let Some(picture) = object.get("picture").cloned() {
            object.entry("image").or_insert(picture);
        }
    }
    value
}

fn normalize_user_info(mut value: Value) -> Result<Value, AuthError> {
    let object = value
        .as_object_mut()
        .ok_or(AuthError::OAuthUserInfoUnavailable)?;
    let verified = object
        .get("email_verified")
        .cloned()
        .filter(|value| !value.is_null())
        .unwrap_or(Value::Bool(false));
    object.insert("emailVerified".into(), verified);
    if let Some(picture) = object.get("picture").cloned() {
        object.insert("image".into(), picture);
    } else {
        object.remove("image");
    }
    Ok(value)
}

fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

fn text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn boolean(value: Option<&Value>) -> Option<bool> {
    match value? {
        Value::Bool(value) => Some(*value),
        _ => None,
    }
}

fn validate_identity(value: &str) -> Result<(), AuthError> {
    if value.trim().is_empty() || matches!(value, "undefined" | "null") {
        Err(AuthError::OAuthUserInfoUnavailable)
    } else {
        Ok(())
    }
}
