use super::{discovery::resolve_providers, provider::GenericOAuthProvider};
use crate::{
    AuthConfig, AuthError, AuthPlugin, OAuthTokens, PluginDescriptor, SocialProvider,
    TokenEndpointAuth,
};
use async_trait::async_trait;
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};

const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "generic-oauth",
    display_name: "Generic OAuth",
    version: "1.7.1",
    dependencies: &[],
    conflicts: &[],
    endpoints: &[],
    cookies: &[],
    rate_limits: &[],
    middleware: &[],
    client: None,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GenericOAuthError {
    #[error("Invalid OAuth configuration")]
    InvalidOAuthConfiguration,
    #[error("Invalid OAuth configuration. Token URL not found.")]
    TokenUrlNotFound,
}

#[derive(Debug, Clone)]
pub struct GenericOAuthTokenRequest {
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct GenericOAuthRefreshContext {
    pub request: Option<crate::OAuthRequestContext>,
}

#[derive(Debug, Clone)]
pub struct GenericOAuthAccountKeyContext {
    pub tokens: OAuthTokens,
    pub profile: Value,
}

pub type GenericOAuthMappedUser = serde_json::Map<String, Value>;

#[async_trait]
pub trait GenericOAuthTokenExchange: Send + Sync {
    async fn exchange(&self, request: GenericOAuthTokenRequest) -> Result<OAuthTokens, AuthError>;
}

#[async_trait]
pub trait GenericOAuthUserInfo: Send + Sync {
    async fn user_info(&self, tokens: &OAuthTokens) -> Result<Option<Value>, AuthError>;
}

#[async_trait]
pub trait GenericOAuthProfileMapper: Send + Sync {
    async fn map_profile(&self, profile: &Value) -> Result<GenericOAuthMappedUser, AuthError>;
}

#[async_trait]
pub trait GenericOAuthAccountSubject: Send + Sync {
    async fn account_subject(
        &self,
        context: &GenericOAuthAccountKeyContext,
    ) -> Result<String, AuthError>;
}

#[async_trait]
pub trait GenericOAuthAccountIssuer: Send + Sync {
    async fn account_issuer(
        &self,
        context: &GenericOAuthAccountKeyContext,
    ) -> Result<String, AuthError>;
}

#[async_trait]
pub trait GenericOAuthRefreshParams: Send + Sync {
    async fn refresh_params(
        &self,
        context: &GenericOAuthRefreshContext,
    ) -> Result<BTreeMap<String, String>, AuthError>;
}

#[derive(Clone)]
pub struct GenericOAuthConfig {
    pub provider_id: String,
    pub name: Option<String>,
    pub account_subject: Option<Arc<dyn GenericOAuthAccountSubject>>,
    pub account_issuer: Option<String>,
    pub account_issuer_resolver: Option<Arc<dyn GenericOAuthAccountIssuer>>,
    pub discovery_url: Option<String>,
    pub discovery_headers: BTreeMap<String, String>,
    pub require_id_token_verification: bool,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub user_info_url: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub disable_provider_logout: bool,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub token_endpoint_auth: Option<TokenEndpointAuth>,
    pub scopes: Vec<String>,
    pub redirect_uri: Option<String>,
    pub response_type: Option<String>,
    pub response_mode: Option<String>,
    pub prompt: Option<String>,
    pub pkce: Option<bool>,
    pub access_type: Option<String>,
    pub access_token_expires_in: Option<i64>,
    pub get_token: Option<Arc<dyn GenericOAuthTokenExchange>>,
    pub get_user_info: Option<Arc<dyn GenericOAuthUserInfo>>,
    pub map_profile_to_user: Option<Arc<dyn GenericOAuthProfileMapper>>,
    pub authorization_url_params: BTreeMap<String, String>,
    pub token_url_params: BTreeMap<String, String>,
    pub refresh_token_params: BTreeMap<String, String>,
    pub refresh_token_params_resolver: Option<Arc<dyn GenericOAuthRefreshParams>>,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub authentication_basic: bool,
    pub authorization_headers: BTreeMap<String, String>,
    pub override_user_info: bool,
    pub require_email_verification: bool,
    pub allow_idp_initiated: bool,
    pub disable_id_token_nonce_binding: bool,
}

impl GenericOAuthConfig {
    pub fn new(provider_id: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            name: None,
            account_subject: None,
            account_issuer: None,
            account_issuer_resolver: None,
            discovery_url: None,
            discovery_headers: BTreeMap::new(),
            require_id_token_verification: false,
            authorization_url: None,
            token_url: None,
            user_info_url: None,
            end_session_endpoint: None,
            post_logout_redirect_uri: None,
            disable_provider_logout: false,
            client_id: client_id.into(),
            client_secret: None,
            token_endpoint_auth: None,
            scopes: Vec::new(),
            redirect_uri: None,
            response_type: None,
            response_mode: None,
            prompt: None,
            pkce: None,
            access_type: None,
            access_token_expires_in: None,
            get_token: None,
            get_user_info: None,
            map_profile_to_user: None,
            authorization_url_params: BTreeMap::new(),
            token_url_params: BTreeMap::new(),
            refresh_token_params: BTreeMap::new(),
            refresh_token_params_resolver: None,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            authentication_basic: false,
            authorization_headers: BTreeMap::new(),
            override_user_info: false,
            require_email_verification: false,
            allow_idp_initiated: false,
            disable_id_token_nonce_binding: false,
        }
    }
}

#[derive(Clone)]
pub struct GenericOAuthPlugin {
    providers: Vec<Arc<GenericOAuthProvider>>,
}

impl GenericOAuthPlugin {
    pub async fn initialize(config: Vec<GenericOAuthConfig>) -> Result<Self, AuthError> {
        let mut seen = std::collections::BTreeSet::new();
        let mut duplicates = std::collections::BTreeSet::new();
        for provider in &config {
            if !seen.insert(provider.provider_id.clone()) {
                duplicates.insert(provider.provider_id.clone());
            }
        }
        if !duplicates.is_empty() {
            eprintln!(
                "Duplicate provider IDs found: {}",
                duplicates.into_iter().collect::<Vec<_>>().join(", ")
            );
        }
        Ok(Self {
            providers: resolve_providers(config).await?,
        })
    }

    pub fn providers(&self) -> impl Iterator<Item = &(dyn SocialProvider + 'static)> {
        self.providers
            .iter()
            .map(|provider| provider.as_ref() as &dyn SocialProvider)
    }
}

#[async_trait]
impl AuthPlugin for GenericOAuthPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        DESCRIPTOR
    }

    fn validate(&self, config: &AuthConfig) -> Result<(), AuthError> {
        if config.base_url().is_none() {
            return Err(AuthError::InvalidConfiguration(
                "a base URL is required when social providers are configured".into(),
            ));
        }
        let existing = config
            .social_providers
            .iter()
            .map(|provider| provider.id())
            .collect::<std::collections::BTreeSet<_>>();
        for provider in &self.providers {
            if existing.contains(provider.id()) {
                eprintln!(
                    "Generic OAuth provider \"{}\" shadows a built-in social provider with the same ID",
                    provider.id()
                );
            }
            provider.validate_configuration()?;
        }
        Ok(())
    }

    fn social_providers(&self) -> Vec<Arc<dyn SocialProvider>> {
        self.providers
            .iter()
            .cloned()
            .map(|provider| provider as Arc<dyn SocialProvider>)
            .collect()
    }
}
