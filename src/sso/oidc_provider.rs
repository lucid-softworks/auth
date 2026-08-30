use super::{SsoOptions, SsoProvider};
use crate::{
    AuthError, GenericOAuthConfig, GenericOAuthMappedUser, GenericOAuthProfileMapper,
    GenericOAuthUserInfo, OAuthTokens, OidcConfig, TokenEndpointAuth,
    generic_oauth::GenericOAuthProvider,
};
use async_trait::async_trait;
use serde_json::{Map, Value, json};
use std::sync::Arc;

pub(super) fn build(
    provider: &SsoProvider,
    redirect_uri: String,
    options: &SsoOptions,
) -> Result<GenericOAuthProvider, &'static str> {
    let config = provider
        .oidc_config
        .as_ref()
        .and_then(Value::as_object)
        .ok_or("provider not found")?;
    let client_id = text(config, "clientId").ok_or("client_id_not_found")?;
    let mut generic = GenericOAuthConfig::new(&provider.provider_id, client_id);
    generic.name = Some(provider.provider_id.clone());
    generic.account_issuer = Some(provider.issuer.clone());
    generic.authorization_url = text(config, "authorizationEndpoint").map(str::to_owned);
    generic.token_url = text(config, "tokenEndpoint").map(str::to_owned);
    generic.user_info_url = text(config, "userInfoEndpoint").map(str::to_owned);
    generic.client_secret = text(config, "clientSecret").map(str::to_owned);
    generic.scopes = strings(config.get("scopes"));
    generic.redirect_uri = Some(redirect_uri);
    generic.pkce = Some(config.get("pkce").and_then(Value::as_bool).unwrap_or(true));
    generic.override_user_info = config
        .get("overrideUserInfo")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    generic.disable_implicit_sign_up = options.disable_implicit_sign_up;
    generic.get_user_info = generic
        .user_info_url
        .as_ref()
        .map(|endpoint| Arc::new(UserInfoFetcher(endpoint.clone())) as Arc<dyn GenericOAuthUserInfo>);
    generic.token_endpoint_auth = match text(config, "tokenEndpointAuthentication") {
        Some("client_secret_post") => Some(TokenEndpointAuth::ClientSecretPost),
        Some("none") => Some(TokenEndpointAuth::None),
        Some("private_key_jwt") => return Err("no_private_key_available"),
        _ => Some(TokenEndpointAuth::ClientSecretBasic),
    };
    generic.map_profile_to_user = Some(Arc::new(ProfileMapper::new(
        config,
        options.trust_email_verified,
    )));
    let oidc = OidcConfig {
        jwks_url: text(config, "jwksEndpoint")
            .unwrap_or("https://invalid.invalid/sso-missing-jwks")
            .into(),
        issuers: vec![provider.issuer.clone()],
        audiences: vec![client_id.into()],
        algorithms: [
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384",
            "ES512", "EdDSA",
        ]
        .map(str::to_owned)
        .into(),
        requires_nonce: false,
        nonce_sha256_fallback: false,
        maximum_age: None,
        dynamic_issuer_template: None,
    };
    Ok(GenericOAuthProvider::new(
        generic,
        Some(provider.issuer.clone()),
        true,
        Some(oidc),
    )
    .with_exact_oidc_errors())
}

struct UserInfoFetcher(String);

#[async_trait]
impl GenericOAuthUserInfo for UserInfoFetcher {
    async fn user_info(&self, tokens: &OAuthTokens) -> Result<Option<Value>, AuthError> {
        let access_token = tokens
            .access_token
            .as_deref()
            .ok_or(AuthError::OAuthUserInfoUnavailable)?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| AuthError::OAuthUserInfoUnavailable)?;
        let response = client
            .get(&self.0)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|_| AuthError::OAuthUserInfoUnavailable)?;
        if !response.status().is_success() || response.status().is_redirection() {
            return Err(AuthError::OAuthUserInfoUnavailable);
        }
        let profile = response
            .json::<Value>()
            .await
            .map_err(|_| AuthError::OAuthUserInfoUnavailable)?;
        Ok(Some(profile))
    }
}

#[derive(Clone)]
struct ProfileMapper {
    email: String,
    name: String,
    image: String,
    email_verified: String,
    trust_email_verified: bool,
    extra: Vec<(String, String)>,
}

impl ProfileMapper {
    fn new(config: &Map<String, Value>, trust_email_verified: bool) -> Self {
        let mapping = config.get("mapping").and_then(Value::as_object);
        Self {
            email: mapped(mapping, "email", "email"),
            name: mapped(mapping, "name", "name"),
            image: mapped(mapping, "image", "picture"),
            email_verified: mapped(mapping, "emailVerified", "email_verified"),
            trust_email_verified,
            extra: mapping
                .and_then(|mapping| mapping.get("extraFields"))
                .and_then(Value::as_object)
                .into_iter()
                .flat_map(|fields| fields.iter())
                .filter_map(|(output, input)| {
                    input
                        .as_str()
                        .map(|input| (output.clone(), input.to_owned()))
                })
                .collect(),
        }
    }
}

#[async_trait]
impl GenericOAuthProfileMapper for ProfileMapper {
    async fn map_profile(&self, profile: &Value) -> Result<GenericOAuthMappedUser, AuthError> {
        let mut mapped = Map::from_iter([
            ("email".into(), claim(profile, &self.email)),
            ("name".into(), claim(profile, &self.name)),
            ("image".into(), claim(profile, &self.image)),
            (
                "emailVerified".into(),
                json!(self.trust_email_verified
                    && provider_email_verified(&claim(profile, &self.email_verified))),
            ),
        ]);
        mapped.extend(
            self.extra
                .iter()
                .map(|(output, input)| (output.clone(), claim(profile, input))),
        );
        Ok(mapped)
    }
}

fn mapped(mapping: Option<&Map<String, Value>>, field: &str, default: &str) -> String {
    mapping
        .and_then(|mapping| mapping.get(field))
        .and_then(Value::as_str)
        .unwrap_or(default)
        .into()
}

fn claim(profile: &Value, field: &str) -> Value {
    profile.get(field).cloned().unwrap_or(Value::Null)
}

fn provider_email_verified(value: &Value) -> bool {
    value == &Value::Bool(true) || value.as_str() == Some("true")
}

fn text<'a>(config: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    config
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}
