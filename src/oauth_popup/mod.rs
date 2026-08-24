use crate::{
    AuthPlugin, PluginClientMetadata, PluginCookie, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod,
};
use async_trait::async_trait;
#[cfg(feature = "axum")]
use std::sync::Arc;

#[cfg(feature = "axum")]
mod axum;
#[cfg(feature = "axum")]
mod callback;
#[cfg(feature = "axum")]
mod completion;
#[cfg(feature = "axum")]
mod cookies;
#[cfg(feature = "axum")]
mod service;
#[cfg(feature = "axum")]
mod start;

pub const OAUTH_POPUP_MESSAGE_TYPE: &str = "better-auth:oauth-popup";
pub const OAUTH_POPUP_DATA_ELEMENT_ID: &str = "better-auth-oauth-popup";
pub const POPUP_MARKER_COOKIE: &str = "oauth_popup";
pub const POPUP_TOKEN_STORAGE_KEY: &str = "better-auth.popup_token";
pub const OAUTH_POPUP_SCRIPT_CSP_HASH: &str = "sha256-tIo2K8VBC9SnhvdZ+9GsGkQoZm+jm/JcxL+d+i8b8KQ=";

const ENDPOINTS: &[PluginEndpoint] = &[PluginEndpoint {
    method: PluginHttpMethod::Get,
    path: "/oauth-popup/start",
    client_method: "signIn.popup",
}];
const COOKIES: &[PluginCookie] = &[PluginCookie {
    name: "better-auth.oauth_popup",
}];

#[derive(Debug, Clone, Copy, Default)]
pub struct OAuthPopupPlugin;

#[async_trait]
impl AuthPlugin for OAuthPopupPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "oauth-popup",
            display_name: "Better Auth OAuth Popup",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            dependencies: &[],
            conflicts: &[],
            endpoints: ENDPOINTS,
            cookies: COOKIES,
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::current(
                "better-auth",
                "better-auth/client/plugins",
                "oauthPopupClient",
            )),
        }
    }

    #[cfg(feature = "axum")]
    fn routes(&self, _service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes()
    }

    #[cfg(feature = "axum")]
    async fn after_response(
        &self,
        service: &crate::AuthService,
        request: &crate::PluginRequestContext,
        response: ::axum::response::Response,
    ) -> ::axum::response::Response {
        axum::after_response(service, request, response).await
    }
}
