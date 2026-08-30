use crate::{AuthPlugin, PluginClientMetadata, PluginDescriptor, PluginEndpoint, PluginHttpMethod};
use async_trait::async_trait;
use std::{borrow::Cow, fmt, sync::Arc};

#[cfg(feature = "axum")]
mod axum;
#[cfg(feature = "axum")]
mod transfer;

const ENDPOINTS: &[PluginEndpoint] = &[
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: Cow::Borrowed("/electron/token"),
        client_method: "electronToken",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: Cow::Borrowed("/electron/init-oauth-proxy"),
        client_method: "electronInitOAuthProxy",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: Cow::Borrowed("/electron/transfer-user"),
        client_method: "electronTransferUser",
    },
];
const CLIENT_ACTIONS: &[&str] = &["getCookie", "authenticate", "requestAuth", "setupMain"];

/// Exact server options published by `@better-auth/electron@1.7.1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectronOptions {
    pub code_expires_in: i64,
    pub redirect_cookie_expires_in: i64,
    pub cookie_prefix: String,
    pub client_id: String,
}

impl Default for ElectronOptions {
    fn default() -> Self {
        Self {
            code_expires_in: 300,
            redirect_cookie_expires_in: 120,
            cookie_prefix: "better-auth".into(),
            client_id: "electron".into(),
        }
    }
}

/// Native server equivalent of `@better-auth/electron@1.7.1`'s `electron()` plugin.
#[derive(Clone)]
pub struct ElectronPlugin {
    options: Arc<ElectronOptions>,
}

impl ElectronPlugin {
    pub fn new(options: ElectronOptions) -> Self {
        Self {
            options: Arc::new(options),
        }
    }

    pub fn options(&self) -> &ElectronOptions {
        &self.options
    }
}

impl Default for ElectronPlugin {
    fn default() -> Self {
        Self::new(ElectronOptions::default())
    }
}

impl fmt::Debug for ElectronPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ElectronPlugin")
            .field("options", &self.options)
            .finish()
    }
}

#[async_trait]
impl AuthPlugin for ElectronPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "electron",
            display_name: "Better Auth Electron",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::pinned_upstream(
                "@better-auth/electron",
                crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
                "@better-auth/electron",
                "electron",
            ),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Borrowed(ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(
                PluginClientMetadata::official(
                    "@better-auth/electron",
                    "@better-auth/electron/client",
                    "electronClient",
                )
                .with_identity("electron", "1.7.1")
                .with_custom_actions(CLIENT_ACTIONS),
            ),
        }
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service, self.options.clone())
    }

    #[cfg(feature = "axum")]
    async fn after_response(
        &self,
        service: &crate::AuthService,
        request: &crate::PluginRequestContext,
        response: ::axum::response::Response,
    ) -> ::axum::response::Response {
        axum::after_response(service, &self.options, request, response).await
    }

    #[cfg(feature = "axum")]
    fn contributes_on_response(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_descriptor_match_the_published_server() {
        assert_eq!(
            ElectronOptions::default(),
            ElectronOptions {
                code_expires_in: 300,
                redirect_cookie_expires_in: 120,
                cookie_prefix: "better-auth".into(),
                client_id: "electron".into(),
            }
        );
        let descriptor = ElectronPlugin::default().descriptor();
        assert_eq!(descriptor.id, "electron");
        assert_eq!(descriptor.endpoints, ENDPOINTS);
        assert!(descriptor.cookies.is_empty());
        assert!(descriptor.rate_limits.is_empty());
        assert!(descriptor.middleware.is_empty());
        let client = descriptor.client.unwrap();
        assert_eq!(client.import_path, "@better-auth/electron/client");
        assert_eq!(client.factory, "electronClient");
        assert_eq!(client.custom_actions, CLIENT_ACTIONS);
        assert!(client.path_methods.is_empty());
    }
}
