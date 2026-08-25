use crate::{
    AuthConfig, AuthError, AuthPlugin, PluginClientMetadata, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod, SessionWithUser,
};
use async_trait::async_trait;
use chrono::Duration;
use std::{collections::BTreeMap, fmt, sync::Arc};

#[cfg(feature = "axum")]
mod axum;

const ENDPOINTS: &[PluginEndpoint] = &[
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: std::borrow::Cow::Borrowed("/one-time-token/generate"),
        client_method: "oneTimeToken.generate",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed("/one-time-token/verify"),
        client_method: "oneTimeToken.verify",
    },
];

/// Framework-neutral context passed to a custom one-time-token generator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OneTimeTokenRequestContext {
    pub method: Option<String>,
    pub path: Option<String>,
    pub query: Option<String>,
    pub headers: BTreeMap<String, String>,
}

#[async_trait]
pub trait OneTimeTokenGenerator: Send + Sync {
    async fn generate(
        &self,
        session: &SessionWithUser,
        context: &OneTimeTokenRequestContext,
    ) -> Result<String, AuthError>;
}

#[async_trait]
pub trait OneTimeTokenHasher: Send + Sync {
    async fn hash(&self, token: &str) -> Result<String, AuthError>;
}

#[derive(Clone, Default)]
pub enum OneTimeTokenStorage {
    #[default]
    Plain,
    Hashed,
    Custom(Arc<dyn OneTimeTokenHasher>),
}

impl fmt::Debug for OneTimeTokenStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain => formatter.write_str("Plain"),
            Self::Hashed => formatter.write_str("Hashed"),
            Self::Custom(_) => formatter.write_str("Custom(..)"),
        }
    }
}

#[derive(Clone)]
pub struct OneTimeTokenConfig {
    /// Token lifetime. Better Auth expresses this option in minutes.
    pub expires_in: Duration,
    pub disable_client_request: bool,
    pub generator: Option<Arc<dyn OneTimeTokenGenerator>>,
    pub disable_set_session_cookie: bool,
    pub token_storage: OneTimeTokenStorage,
    pub set_ott_header_on_new_session: bool,
}

impl Default for OneTimeTokenConfig {
    fn default() -> Self {
        Self {
            expires_in: Duration::minutes(3),
            disable_client_request: false,
            generator: None,
            disable_set_session_cookie: false,
            token_storage: OneTimeTokenStorage::Plain,
            set_ott_header_on_new_session: false,
        }
    }
}

impl fmt::Debug for OneTimeTokenConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OneTimeTokenConfig")
            .field("expires_in", &self.expires_in)
            .field("disable_client_request", &self.disable_client_request)
            .field("has_generator", &self.generator.is_some())
            .field(
                "disable_set_session_cookie",
                &self.disable_set_session_cookie,
            )
            .field("token_storage", &self.token_storage)
            .field(
                "set_ott_header_on_new_session",
                &self.set_ott_header_on_new_session,
            )
            .finish()
    }
}

#[derive(Clone)]
pub struct OneTimeTokenPlugin {
    config: Arc<OneTimeTokenConfig>,
}

impl OneTimeTokenPlugin {
    pub fn new(config: OneTimeTokenConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    pub fn config(&self) -> &OneTimeTokenConfig {
        &self.config
    }
}

impl Default for OneTimeTokenPlugin {
    fn default() -> Self {
        Self::new(OneTimeTokenConfig::default())
    }
}

impl fmt::Debug for OneTimeTokenPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OneTimeTokenPlugin")
            .field("config", &self.config)
            .finish()
    }
}

#[async_trait]
impl AuthPlugin for OneTimeTokenPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "one-time-token",
            display_name: "Better Auth One-Time Token",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::better_auth_plugin("oneTimeToken"),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::official(
                "better-auth",
                "better-auth/client/plugins",
                "oneTimeTokenClient",
            )),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        // Better Auth permits zero and negative expirations; they simply
        // produce tokens which cannot subsequently be redeemed.
        Ok(())
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service, self.config.clone())
    }

    #[cfg(feature = "axum")]
    async fn after_response(
        &self,
        service: &crate::AuthService,
        request: &crate::PluginRequestContext,
        response: ::axum::response::Response,
    ) -> ::axum::response::Response {
        axum::after_response(service, &self.config, request, response).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OneTimeTokenError {
    #[error("Client requests are disabled")]
    ClientRequestsDisabled,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Session not found")]
    SessionNotFound,
    #[error("Session expired")]
    SessionExpired,
}
