mod config;
pub(crate) mod error;
#[cfg(feature = "axum")]
mod http;
mod validation;

pub use config::{
    UsernameConfig, UsernameNormalizer, UsernameValidationOrder, UsernameValidationTiming,
    UsernameValidator,
};
pub use error::UsernameError;

use crate::{AuthPlugin, PluginClientMetadata, PluginDescriptor, PluginEndpoint, PluginHttpMethod};

const ENDPOINTS: &[PluginEndpoint] = &[
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed("/sign-in/username"),
        client_method: "signIn.username",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed("/is-username-available"),
        client_method: "isUsernameAvailable",
    },
];

#[derive(Debug, Clone, Default)]
pub struct UsernamePlugin {
    config: UsernameConfig,
}

impl UsernamePlugin {
    pub fn new(config: UsernameConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &UsernameConfig {
        &self.config
    }
}

#[async_trait::async_trait]
impl AuthPlugin for UsernamePlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "username",
            display_name: "Username",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::current(
                "better-auth",
                "better-auth/client/plugins",
                "usernameClient",
            )),
        }
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: std::sync::Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        http::routes(service)
    }
}
