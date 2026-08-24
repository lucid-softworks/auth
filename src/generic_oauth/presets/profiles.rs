use super::{
    GumroadOptions, HubSpotOptions, LineOptions, PatreonOptions, SlackOptions, YandexOptions,
    configured,
};
use crate::{
    AuthError, GenericOAuthAccountKeyContext, GenericOAuthAccountSubject, GenericOAuthConfig,
    GenericOAuthUserInfo, OAuthTokens,
};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::Arc;

pub fn gumroad(options: GumroadOptions) -> GenericOAuthConfig {
    let mut config = configured("gumroad", options.0, &["view_profile"]);
    config.authorization_url = Some("https://gumroad.com/oauth/authorize".into());
    config.token_url = Some("https://api.gumroad.com/oauth/token".into());
    config.get_user_info = Some(Arc::new(GumroadProfile));
    config.account_subject = Some(Arc::new(FieldSubject("id")));
    config
}

pub fn hubspot(options: HubSpotOptions) -> GenericOAuthConfig {
    let mut config = configured("hubspot", options.0, &["oauth"]);
    config.authorization_url = Some("https://app.hubspot.com/oauth/authorize".into());
    config.token_url = Some("https://api.hubapi.com/oauth/v1/token".into());
    config.authentication_basic = false;
    config.get_user_info = Some(Arc::new(HubSpotProfile));
    config.account_subject = Some(Arc::new(FieldSubject("id")));
    config
}

pub fn line(options: LineOptions) -> GenericOAuthConfig {
    let id = options.provider_id.as_deref().unwrap_or("line");
    let mut config = configured(id, options.base, &["openid", "profile", "email"]);
    config.authorization_url = Some("https://access.line.me/oauth2/v2.1/authorize".into());
    config.token_url = Some("https://api.line.me/oauth2/v2.1/token".into());
    config.user_info_url = Some("https://api.line.me/oauth2/v2.1/userinfo".into());
    config.account_issuer = Some("https://access.line.me".into());
    config.get_user_info = Some(Arc::new(LineProfile));
    config.account_subject = Some(Arc::new(FieldSubject("sub")));
    config
}

pub fn patreon(options: PatreonOptions) -> GenericOAuthConfig {
    let mut config = configured("patreon", options.0, &["identity[email]"]);
    config.authorization_url = Some("https://www.patreon.com/oauth2/authorize".into());
    config.token_url = Some("https://www.patreon.com/api/oauth2/token".into());
    config.get_user_info = Some(Arc::new(PatreonProfile));
    config.account_subject = Some(Arc::new(FieldSubject("id")));
    config
}

pub fn slack(options: SlackOptions) -> GenericOAuthConfig {
    let mut config = configured("slack", options.0, &["openid", "profile", "email"]);
    config.authorization_url = Some("https://slack.com/openid/connect/authorize".into());
    config.token_url = Some("https://slack.com/api/openid.connect.token".into());
    config.user_info_url = Some("https://slack.com/api/openid.connect.userInfo".into());
    config.account_issuer = Some("https://slack.com".into());
    config.get_user_info = Some(Arc::new(SlackProfile));
    config.account_subject = Some(Arc::new(FieldSubject("sub")));
    config
}

pub fn yandex(options: YandexOptions) -> GenericOAuthConfig {
    let mut config = configured(
        "yandex",
        options.0,
        &["login:info", "login:email", "login:avatar"],
    );
    config.authorization_url = Some("https://oauth.yandex.com/authorize".into());
    config.token_url = Some("https://oauth.yandex.com/token".into());
    config.get_user_info = Some(Arc::new(YandexProfile));
    config.account_subject = Some(Arc::new(FieldSubject("id")));
    config
}

struct FieldSubject(&'static str);

#[async_trait]
impl GenericOAuthAccountSubject for FieldSubject {
    async fn account_subject(
        &self,
        context: &GenericOAuthAccountKeyContext,
    ) -> Result<String, AuthError> {
        Ok(text(context.profile.get(self.0)).unwrap_or_default())
    }
}

struct GumroadProfile;

#[async_trait]
impl GenericOAuthUserInfo for GumroadProfile {
    async fn user_info(&self, tokens: &OAuthTokens) -> Result<Option<Value>, AuthError> {
        let Some(profile) = bearer_json(
            "https://api.gumroad.com/v2/user",
            tokens.access_token.as_deref(),
        )
        .await
        else {
            return Ok(None);
        };
        if profile.get("success").and_then(Value::as_bool) != Some(true) {
            return Ok(None);
        }
        let Some(user) = profile.get("user") else {
            return Ok(None);
        };
        Ok(Some(json!({
            "id": user.get("user_id").cloned().unwrap_or(Value::Null),
            "name": user.get("name").cloned().unwrap_or(Value::Null),
            "email": user.get("email").cloned().unwrap_or(Value::Null),
            "image": user.get("profile_url").cloned().unwrap_or(Value::Null),
            "emailVerified": false,
        })))
    }
}

struct HubSpotProfile;

#[async_trait]
impl GenericOAuthUserInfo for HubSpotProfile {
    async fn user_info(&self, tokens: &OAuthTokens) -> Result<Option<Value>, AuthError> {
        let Some(access_token) = tokens.access_token.as_deref() else {
            return Ok(None);
        };
        let endpoint = format!("https://api.hubapi.com/oauth/v1/access-tokens/{access_token}");
        let response = reqwest::Client::new()
            .get(endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .send()
            .await
            .ok();
        let Some(profile) = successful_json(response).await else {
            return Ok(None);
        };
        let id = profile
            .get("user_id")
            .cloned()
            .or_else(|| profile.pointer("/signed_access_token/userId").cloned());
        if id.as_ref().is_none_or(is_json_falsy) {
            return Ok(None);
        }
        Ok(Some(json!({
            "id": id,
            "name": profile.get("user").cloned().unwrap_or(Value::Null),
            "email": profile.get("user").cloned().unwrap_or(Value::Null),
            "emailVerified": false,
        })))
    }
}

struct LineProfile;

#[async_trait]
impl GenericOAuthUserInfo for LineProfile {
    async fn user_info(&self, tokens: &OAuthTokens) -> Result<Option<Value>, AuthError> {
        let profile = if let Some(token) = tokens.id_token.as_deref() {
            jsonwebtoken::dangerous::insecure_decode::<Value>(token)
                .ok()
                .map(|decoded| decoded.claims)
        } else {
            None
        };
        let profile = match profile {
            Some(profile) => profile,
            None => {
                let Some(profile) = bearer_json(
                    "https://api.line.me/oauth2/v2.1/userinfo",
                    tokens.access_token.as_deref(),
                )
                .await
                else {
                    return Ok(None);
                };
                profile
            }
        };
        Ok(Some(json!({
            "sub": profile.get("sub").cloned().unwrap_or(Value::Null),
            "name": profile.get("name").cloned().unwrap_or(Value::Null),
            "email": profile.get("email").cloned().unwrap_or(Value::Null),
            "image": profile.get("picture").cloned().unwrap_or(Value::Null),
            "emailVerified": false,
        })))
    }
}

struct PatreonProfile;

#[async_trait]
impl GenericOAuthUserInfo for PatreonProfile {
    async fn user_info(&self, tokens: &OAuthTokens) -> Result<Option<Value>, AuthError> {
        let endpoint = "https://www.patreon.com/api/oauth2/v2/identity?fields[user]=email,full_name,image_url,is_email_verified";
        let Some(profile) = bearer_json(endpoint, tokens.access_token.as_deref()).await else {
            return Ok(None);
        };
        let Some(data) = profile.get("data") else {
            return Ok(None);
        };
        let Some(attributes) = data.get("attributes") else {
            return Ok(None);
        };
        Ok(Some(json!({
            "id": data.get("id").cloned().unwrap_or(Value::Null),
            "name": attributes.get("full_name").cloned().unwrap_or(Value::Null),
            "email": attributes.get("email").cloned().unwrap_or(Value::Null),
            "image": attributes.get("image_url").cloned().unwrap_or(Value::Null),
            "emailVerified": attributes.get("is_email_verified").cloned().unwrap_or(Value::Null),
        })))
    }
}

struct SlackProfile;

#[async_trait]
impl GenericOAuthUserInfo for SlackProfile {
    async fn user_info(&self, tokens: &OAuthTokens) -> Result<Option<Value>, AuthError> {
        let Some(profile) = bearer_json(
            "https://slack.com/api/openid.connect.userInfo",
            tokens.access_token.as_deref(),
        )
        .await
        else {
            return Ok(None);
        };
        Ok(Some(json!({
            "sub": profile.get("sub").cloned().unwrap_or(Value::Null),
            "name": profile.get("name").cloned().unwrap_or(Value::Null),
            "email": profile.get("email").cloned().unwrap_or(Value::Null),
            "image": profile.get("picture").cloned().or_else(|| profile.get("https://slack.com/user_image_512").cloned()).unwrap_or(Value::Null),
            "emailVerified": profile.get("email_verified").cloned().unwrap_or(Value::Bool(false)),
        })))
    }
}

struct YandexProfile;

#[async_trait]
impl GenericOAuthUserInfo for YandexProfile {
    async fn user_info(&self, tokens: &OAuthTokens) -> Result<Option<Value>, AuthError> {
        let Some(access_token) = tokens.access_token.as_deref() else {
            return Ok(None);
        };
        let response = reqwest::Client::new()
            .get("https://login.yandex.ru/info?format=json")
            .header("authorization", format!("OAuth {access_token}"))
            .send()
            .await
            .ok();
        let Some(profile) = successful_json(response).await else {
            return Ok(None);
        };
        let email = text(profile.get("default_email")).or_else(|| {
            profile
                .get("emails")
                .and_then(Value::as_array)
                .and_then(|emails| emails.first())
                .and_then(|email| text(Some(email)))
        });
        let Some(email) = email.filter(|email| !email.is_empty()) else {
            return Ok(None);
        };
        let name = ["display_name", "real_name", "first_name", "login"]
            .iter()
            .find_map(|field| text(profile.get(*field)));
        let avatar = text(profile.get("default_avatar_id"))
            .filter(|id| !id.is_empty())
            .filter(|_| profile.get("is_avatar_empty").and_then(Value::as_bool) != Some(true))
            .map(|id| format!("https://avatars.yandex.net/get-yapic/{id}/islands-200"));
        Ok(Some(json!({
            "id": profile.get("id").cloned().unwrap_or(Value::Null),
            "name": name,
            "email": email,
            "image": avatar,
            "emailVerified": false,
        })))
    }
}

async fn bearer_json(endpoint: &str, access_token: Option<&str>) -> Option<Value> {
    let access_token = access_token?;
    let response = reqwest::Client::new()
        .get(endpoint)
        .bearer_auth(access_token)
        .send()
        .await
        .ok();
    successful_json(response).await
}

async fn successful_json(response: Option<reqwest::Response>) -> Option<Value> {
    let response = response?;
    response.status().is_success().then_some(())?;
    response.json().await.ok()
}

fn text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn is_json_falsy(value: &Value) -> bool {
    matches!(value, Value::Null | Value::Bool(false))
        || value.as_str().is_some_and(str::is_empty)
        || value.as_f64() == Some(0.0)
}
