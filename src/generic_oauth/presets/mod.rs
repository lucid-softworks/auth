mod oidc;
mod profiles;

use crate::TokenEndpointAuth;

pub use oidc::{auth0, keycloak, microsoft_entra_id, okta};
pub use profiles::{gumroad, hubspot, line, patreon, slack, yandex};

#[derive(Clone, Default)]
pub struct BaseOAuthProviderOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub token_endpoint_auth: Option<TokenEndpointAuth>,
    pub scopes: Option<Vec<String>>,
    pub redirect_uri: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub disable_provider_logout: bool,
    pub pkce: Option<bool>,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub override_user_info: bool,
}

#[derive(Clone)]
pub struct Auth0Options {
    pub base: BaseOAuthProviderOptions,
    pub domain: String,
}

#[derive(Clone)]
pub struct GumroadOptions(pub BaseOAuthProviderOptions);

#[derive(Clone)]
pub struct HubSpotOptions(pub BaseOAuthProviderOptions);

#[derive(Clone)]
pub struct KeycloakOptions {
    pub base: BaseOAuthProviderOptions,
    pub issuer: String,
}

#[derive(Clone)]
pub struct LineOptions {
    pub base: BaseOAuthProviderOptions,
    pub provider_id: Option<String>,
}

#[derive(Clone)]
pub struct MicrosoftEntraIdOptions {
    pub base: BaseOAuthProviderOptions,
    pub tenant_id: String,
}

#[derive(Clone)]
pub struct OktaOptions {
    pub base: BaseOAuthProviderOptions,
    pub issuer: String,
}

#[derive(Clone)]
pub struct PatreonOptions(pub BaseOAuthProviderOptions);

#[derive(Clone)]
pub struct SlackOptions(pub BaseOAuthProviderOptions);

#[derive(Clone)]
pub struct YandexOptions(pub BaseOAuthProviderOptions);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GenericOAuthPresetError {
    #[error(
        "The generic microsoftEntraId helper requires a concrete Microsoft Entra tenant GUID. Use the built-in Microsoft provider for common, organizations, or consumers."
    )]
    MicrosoftTenantMustBeConcrete,
}

pub(super) fn configured(
    provider_id: &str,
    base: BaseOAuthProviderOptions,
    default_scopes: &[&str],
) -> crate::GenericOAuthConfig {
    let mut config = crate::GenericOAuthConfig::new(provider_id, base.client_id);
    config.client_secret = base.client_secret;
    config.token_endpoint_auth = base.token_endpoint_auth;
    config.scopes = base.scopes.unwrap_or_else(|| {
        default_scopes
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect()
    });
    config.redirect_uri = base.redirect_uri;
    config.end_session_endpoint = base.end_session_endpoint;
    config.post_logout_redirect_uri = base.post_logout_redirect_uri;
    config.disable_provider_logout = base.disable_provider_logout;
    config.pkce = base.pkce;
    config.disable_implicit_sign_up = base.disable_implicit_sign_up;
    config.disable_sign_up = base.disable_sign_up;
    config.override_user_info = base.override_user_info;
    config
}
