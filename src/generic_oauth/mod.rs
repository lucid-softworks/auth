//! Better Auth 1.7.2 generic OAuth plugin compatibility.

mod authorization;
mod discovery;
mod presets;
mod profile;
mod provider;
mod token;
mod types;

pub use presets::{
    Auth0Options, BaseOAuthProviderOptions, GenericOAuthPresetError, GumroadOptions,
    HubSpotOptions, KeycloakOptions, LineOptions, MicrosoftEntraIdOptions, OktaOptions,
    PatreonOptions, SlackOptions, YandexOptions, auth0, gumroad, hubspot, keycloak, line,
    microsoft_entra_id, okta, patreon, slack, yandex,
};
pub use types::{
    GenericOAuthAccountIssuer, GenericOAuthAccountKeyContext, GenericOAuthAccountSubject,
    GenericOAuthConfig, GenericOAuthError, GenericOAuthMappedUser, GenericOAuthPlugin,
    GenericOAuthProfileMapper, GenericOAuthRefreshContext, GenericOAuthRefreshParams,
    GenericOAuthTokenExchange, GenericOAuthTokenRequest, GenericOAuthUserInfo,
};
#[cfg(feature = "axum")]
pub(crate) use provider::GenericOAuthProvider;

pub const INVALID_OAUTH_CONFIGURATION: &str = "Invalid OAuth configuration";
pub const TOKEN_URL_NOT_FOUND: &str = "Invalid OAuth configuration. Token URL not found.";
