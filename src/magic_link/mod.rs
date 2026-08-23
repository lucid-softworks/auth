#[cfg(feature = "axum")]
use crate::AuthService;
use crate::{
    AuthConfig, AuthError, AuthPlugin, PluginClientMetadata, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod, PluginRateLimit,
};
use async_trait::async_trait;
use chrono::Duration;
use serde_json::{Map, Value};
use std::sync::Arc;

#[cfg(feature = "axum")]
mod axum;

const ENDPOINTS: &[PluginEndpoint] = &[
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: "/sign-in/magic-link",
        client_method: "signIn.magicLink",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: "/magic-link/verify",
        client_method: "magicLink.verify",
    },
];

const RATE_LIMITS: &[PluginRateLimit] = &[
    PluginRateLimit {
        path: "/sign-in/magic-link",
        window_seconds: 60,
        max_requests: 5,
    },
    PluginRateLimit {
        path: "/magic-link/verify",
        window_seconds: 60,
        max_requests: 5,
    },
];

#[derive(Clone)]
pub struct MagicLinkEmail {
    pub email: String,
    pub url: String,
    pub token: String,
    pub metadata: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MagicLinkRequestContext {
    pub origin: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[async_trait]
pub trait MagicLinkSender: Send + Sync {
    async fn send(
        &self,
        email: MagicLinkEmail,
        context: MagicLinkRequestContext,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait MagicLinkTokenGenerator: Send + Sync {
    async fn generate(&self, email: &str) -> Result<String, AuthError>;
}

#[async_trait]
pub trait MagicLinkTokenHasher: Send + Sync {
    async fn hash(&self, token: &str) -> Result<String, AuthError>;
}

#[derive(Clone, Default)]
pub enum MagicLinkTokenStorage {
    #[default]
    Plain,
    Hashed,
    Custom(Arc<dyn MagicLinkTokenHasher>),
}

#[derive(Clone)]
pub struct MagicLinkConfig {
    pub sender: Arc<dyn MagicLinkSender>,
    pub expires_in: Duration,
    pub disable_sign_up: bool,
    pub token_storage: MagicLinkTokenStorage,
    pub token_generator: Option<Arc<dyn MagicLinkTokenGenerator>>,
    /// Better Auth 1.7.1 always consumes on the first attempt; values other
    /// than one are retained as configuration metadata but intentionally ignored.
    pub allowed_attempts: u32,
    pub rate_limit_window: Duration,
    pub rate_limit_max: usize,
}

impl MagicLinkConfig {
    pub fn new(sender: Arc<dyn MagicLinkSender>) -> Self {
        Self {
            sender,
            expires_in: Duration::minutes(5),
            disable_sign_up: false,
            token_storage: MagicLinkTokenStorage::Plain,
            token_generator: None,
            allowed_attempts: 1,
            rate_limit_window: Duration::minutes(1),
            rate_limit_max: 5,
        }
    }
}

#[derive(Clone)]
pub struct MagicLinkPlugin {
    config: Arc<MagicLinkConfig>,
}

impl MagicLinkPlugin {
    pub fn new(config: MagicLinkConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

#[async_trait]
impl AuthPlugin for MagicLinkPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "magic-link",
            display_name: "Better Auth Magic Link",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            dependencies: &[],
            conflicts: &[],
            endpoints: ENDPOINTS,
            cookies: &[],
            rate_limits: RATE_LIMITS,
            middleware: &[],
            client: Some(PluginClientMetadata::current(
                "better-auth",
                "better-auth/client/plugins",
                "magicLinkClient",
            )),
        }
    }

    fn validate(&self, config: &AuthConfig) -> Result<(), AuthError> {
        if config.base_url().is_none() {
            return Err(AuthError::InvalidConfiguration(
                "a base URL is required when the magic-link plugin is enabled".into(),
            ));
        }
        if self.config.expires_in <= Duration::zero()
            || self.config.rate_limit_window <= Duration::zero()
            || self.config.rate_limit_max == 0
        {
            return Err(AuthError::InvalidConfiguration(
                "magic-link expiry and rate-limit values must be positive".into(),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service, self.config.clone())
    }
}
