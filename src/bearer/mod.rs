use crate::{AuthPlugin, PluginDescriptor};
use async_trait::async_trait;

#[cfg(feature = "axum")]
mod request;
#[cfg(feature = "axum")]
mod response;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BearerConfig {
    pub require_signature: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BearerPlugin {
    config: BearerConfig,
}

impl BearerPlugin {
    pub const fn new(config: BearerConfig) -> Self {
        Self { config }
    }

    pub const fn config(&self) -> &BearerConfig {
        &self.config
    }
}

#[async_trait]
impl AuthPlugin for BearerPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "bearer",
            display_name: "Better Auth Bearer",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            dependencies: &[],
            conflicts: &[],
            endpoints: &[],
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    #[cfg(feature = "axum")]
    async fn after_response(
        &self,
        service: &crate::AuthService,
        _request: &crate::PluginRequestContext,
        response: ::axum::response::Response,
    ) -> ::axum::response::Response {
        response::expose_session_cookie(service, response)
    }
}

#[cfg(feature = "axum")]
pub(crate) use request::session_token;
