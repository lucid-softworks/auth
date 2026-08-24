use super::{
    Auth0Options, GenericOAuthPresetError, KeycloakOptions, MicrosoftEntraIdOptions, OktaOptions,
    configured,
};
use crate::{
    AuthError, GenericOAuthAccountKeyContext, GenericOAuthAccountSubject, GenericOAuthConfig,
    GenericOAuthUserInfo, OAuthTokens,
};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

pub fn auth0(options: Auth0Options) -> GenericOAuthConfig {
    let domain = options
        .domain
        .strip_prefix("https://")
        .or_else(|| options.domain.strip_prefix("http://"))
        .unwrap_or(&options.domain)
        .trim_end_matches('/')
        .to_owned();
    let mut config = configured("auth0", options.base, &["openid", "profile", "email"]);
    config.discovery_url = Some(format!("https://{domain}/.well-known/openid-configuration"));
    config.account_issuer = Some(format!("https://{domain}/"));
    config
}

pub fn keycloak(options: KeycloakOptions) -> GenericOAuthConfig {
    issuer_preset("keycloak", options.base, options.issuer)
}

pub fn okta(options: OktaOptions) -> GenericOAuthConfig {
    issuer_preset("okta", options.base, options.issuer)
}

fn issuer_preset(
    id: &str,
    base: super::BaseOAuthProviderOptions,
    issuer: String,
) -> GenericOAuthConfig {
    let issuer = issuer
        .strip_suffix('/')
        .map(str::to_owned)
        .unwrap_or(issuer);
    let mut config = configured(id, base, &["openid", "profile", "email"]);
    config.discovery_url = Some(format!("{issuer}/.well-known/openid-configuration"));
    config.account_issuer = Some(issuer);
    config
}

pub fn microsoft_entra_id(
    options: MicrosoftEntraIdOptions,
) -> Result<GenericOAuthConfig, GenericOAuthPresetError> {
    let tenant = options.tenant_id.to_lowercase();
    if tenant.len() != 36 || uuid::Uuid::parse_str(&tenant).is_err() {
        return Err(GenericOAuthPresetError::MicrosoftTenantMustBeConcrete);
    }
    let root = format!("https://login.microsoftonline.com/{tenant}");
    let mut config = configured(
        "microsoft-entra-id",
        options.base,
        &["openid", "profile", "email"],
    );
    config.authorization_url = Some(format!("{root}/oauth2/v2.0/authorize"));
    config.token_url = Some(format!("{root}/oauth2/v2.0/token"));
    config.discovery_url = Some(format!("{root}/v2.0/.well-known/openid-configuration"));
    config.user_info_url = Some("https://graph.microsoft.com/oidc/userinfo".into());
    config.require_id_token_verification = true;
    config.account_subject = Some(Arc::new(MicrosoftSubject));
    config.get_user_info = Some(Arc::new(MicrosoftProfile));
    Ok(config)
}

struct MicrosoftSubject;

#[async_trait]
impl GenericOAuthAccountSubject for MicrosoftSubject {
    async fn account_subject(
        &self,
        context: &GenericOAuthAccountKeyContext,
    ) -> Result<String, AuthError> {
        Ok(context
            .profile
            .get("oid")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned())
    }
}

struct MicrosoftProfile;

#[async_trait]
impl GenericOAuthUserInfo for MicrosoftProfile {
    async fn user_info(&self, tokens: &OAuthTokens) -> Result<Option<Value>, AuthError> {
        let Some(id_token) = tokens.id_token.as_deref() else {
            return Ok(None);
        };
        let Ok(decoded) = jsonwebtoken::dangerous::insecure_decode::<Value>(id_token) else {
            return Ok(None);
        };
        let claims = decoded.claims;
        let oid = claims
            .get("oid")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty());
        if oid.is_none() {
            return Ok(None);
        }
        let token_user = microsoft_user_info(&claims, None);
        let Some(token_sub) = claims.get("sub").and_then(Value::as_str) else {
            return Ok(Some(token_user));
        };
        let Some(graph) = fetch_graph(tokens.access_token.as_deref()).await else {
            return Ok(Some(token_user));
        };
        if graph.get("sub").and_then(Value::as_str) != Some(token_sub) {
            return Ok(Some(token_user));
        }
        Ok(Some(microsoft_user_info(&claims, Some(&graph))))
    }
}

fn microsoft_user_info(token: &Value, graph: Option<&Value>) -> Value {
    let mut object = graph
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(token) = token.as_object() {
        object.extend(token.clone());
    }
    let token_name = profile_name(token);
    let graph_name = graph.and_then(profile_name);
    let name = token_name.or(graph_name);
    let email = text(token, &["email"])
        .or_else(|| graph.and_then(|profile| text(profile, &["email"])))
        .or_else(|| text(token, &["preferred_username"]))
        .or_else(|| graph.and_then(|profile| text(profile, &["preferred_username"])));
    let image =
        text(token, &["picture"]).or_else(|| graph.and_then(|profile| text(profile, &["picture"])));
    let verified = token
        .get("email_verified")
        .and_then(Value::as_bool)
        .or_else(|| graph.and_then(|profile| profile.get("email_verified")?.as_bool()))
        .unwrap_or(false);
    if let Some(name) = name {
        object.insert("name".into(), Value::String(name));
    }
    if let Some(email) = email {
        object.insert("email".into(), Value::String(email));
    }
    if let Some(image) = image {
        object.insert("image".into(), Value::String(image));
    }
    object.insert("emailVerified".into(), Value::Bool(verified));
    Value::Object(object)
}

fn profile_name(profile: &Value) -> Option<String> {
    text(profile, &["name"]).or_else(|| {
        let given = text(profile, &["given_name", "givenname"]).unwrap_or_default();
        let family = text(profile, &["family_name", "familyname"]).unwrap_or_default();
        let joined = format!("{given} {family}").trim().to_owned();
        (!joined.is_empty()).then_some(joined)
    })
}
async fn fetch_graph(access_token: Option<&str>) -> Option<Value> {
    let access_token = access_token?;
    let response = reqwest::Client::new()
        .get("https://graph.microsoft.com/oidc/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .ok()?;
    response.status().is_success().then_some(())?;
    response.json().await.ok()
}

fn text(value: &Value, fields: &[&str]) -> Option<String> {
    fields.iter().find_map(|field| {
        value
            .get(*field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}
