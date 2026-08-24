#[cfg(feature = "axum")]
pub(crate) mod axum;

use crate::{
    AuthConfig, AuthPlugin, PluginClientMetadata, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod,
};
use async_trait::async_trait;
use std::sync::Arc;

const ENDPOINTS: &[PluginEndpoint] = &[
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: "/multi-session/list-device-sessions",
        client_method: "multiSession.listDeviceSessions",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: "/multi-session/set-active",
        client_method: "multiSession.setActive",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: "/multi-session/revoke",
        client_method: "multiSession.revoke",
    },
];

pub const INVALID_SESSION_TOKEN: &str = "Invalid session token";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MultiSessionConfig {
    pub maximum_sessions: f64,
}

impl Default for MultiSessionConfig {
    fn default() -> Self {
        Self {
            maximum_sessions: 5.0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MultiSessionPlugin {
    pub(crate) config: Arc<MultiSessionConfig>,
}

impl MultiSessionPlugin {
    pub fn new(config: MultiSessionConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    pub fn config(&self) -> &MultiSessionConfig {
        &self.config
    }
}

#[async_trait]
impl AuthPlugin for MultiSessionPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "multi-session",
            display_name: "Better Auth Multi Session",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            dependencies: &[],
            conflicts: &[],
            endpoints: ENDPOINTS,
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::current(
                "better-auth",
                "better-auth/client/plugins",
                "multiSessionClient",
            )),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), crate::AuthError> {
        Ok(())
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service, self.config.clone())
    }
}
