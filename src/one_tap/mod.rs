use crate::{
    AuthConfig, AuthError, AuthPlugin, PluginClientMetadata, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod,
};
use async_trait::async_trait;
use std::sync::Arc;

#[cfg(feature = "axum")]
mod axum;

const ENDPOINTS: &[PluginEndpoint] = &[PluginEndpoint {
    method: PluginHttpMethod::Post,
    path: std::borrow::Cow::Borrowed("/one-tap/callback"),
    client_method: "oneTap",
}];

#[derive(Clone)]
pub struct OneTapConfig {
    pub client_id: Option<String>,
    pub disable_signup: bool,
    pub(crate) verifier: crate::oauth::google_id_token::GoogleIdTokenVerifier,
}

impl std::fmt::Debug for OneTapConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OneTapConfig")
            .field("client_id", &self.client_id)
            .field("disable_signup", &self.disable_signup)
            .finish_non_exhaustive()
    }
}

impl Default for OneTapConfig {
    fn default() -> Self {
        Self {
            client_id: None,
            disable_signup: false,
            verifier: crate::oauth::google_id_token::GoogleIdTokenVerifier::production(),
        }
    }
}

impl OneTapConfig {
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    pub fn with_disable_signup(mut self, disable_signup: bool) -> Self {
        self.disable_signup = disable_signup;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OneTapError {
    #[error(
        "Google client ID is required for One Tap. Set it on the oneTap plugin (clientId) or on socialProviders.google."
    )]
    MissingClientId,
    #[error("invalid id token")]
    InvalidIdToken,
    #[error("Email not available in token")]
    EmailNotAvailable,
}

#[derive(Clone)]
pub struct OneTapPlugin {
    pub(crate) config: Arc<OneTapConfig>,
}

impl OneTapPlugin {
    pub fn new(config: OneTapConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    pub(crate) fn config(&self) -> &OneTapConfig {
        &self.config
    }
}

#[async_trait]
impl AuthPlugin for OneTapPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "one-tap",
            display_name: "Better Auth Google One Tap",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::better_auth_plugin("oneTap"),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::official(
                "better-auth",
                "better-auth/client/plugins",
                "oneTapClient",
            )),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        Ok(())
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service, self.config.clone())
    }
}
