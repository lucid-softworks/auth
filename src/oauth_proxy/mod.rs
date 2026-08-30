mod config;
#[cfg(feature = "axum")]
pub(crate) mod crypto;
#[cfg(feature = "axum")]
pub(crate) mod payload;
#[cfg(feature = "axum")]
pub(crate) mod service;
#[cfg(feature = "axum")]
pub(crate) mod url;

pub use config::{OAuthProxyConfig, OAuthProxySecret, OAuthProxyVersionedSecret};

use crate::{AuthPlugin, PluginDescriptor, PluginEndpoint, PluginHttpMethod};
use async_trait::async_trait;
use std::{borrow::Cow, fmt, sync::Arc};

const ENDPOINTS: &[PluginEndpoint] = &[PluginEndpoint {
    method: PluginHttpMethod::Get,
    path: Cow::Borrowed("/oauth-proxy-callback"),
    client_method: "oAuthProxy",
}];

#[derive(Clone)]
pub struct OAuthProxyPlugin {
    config: Arc<OAuthProxyConfig>,
}

impl OAuthProxyPlugin {
    pub fn new(config: OAuthProxyConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    pub fn config(&self) -> &OAuthProxyConfig {
        &self.config
    }
}

impl Default for OAuthProxyPlugin {
    fn default() -> Self {
        Self::new(OAuthProxyConfig::default())
    }
}

impl fmt::Debug for OAuthProxyPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthProxyPlugin")
            .field("config", &self.config)
            .finish()
    }
}

#[async_trait]
impl AuthPlugin for OAuthProxyPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "oauth-proxy",
            display_name: "Better Auth OAuth Proxy",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::better_auth_plugin("oAuthProxy"),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Borrowed(ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    #[cfg(feature = "axum")]
    fn routes(&self, _service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        vec![crate::AxumPluginRoute::new(
            "/oauth-proxy-callback",
            axum::routing::get(crate::axum::oauth_proxy::oauth_proxy_callback),
        )]
    }

    #[cfg(feature = "axum")]
    async fn after_response(
        &self,
        service: &crate::AuthService,
        request: &crate::PluginRequestContext,
        response: axum::response::Response,
    ) -> axum::response::Response {
        crate::axum::oauth_proxy::after_response(service, self, request, response)
    }

    #[cfg(feature = "axum")]
    fn contributes_on_response(&self) -> bool {
        true
    }
}
