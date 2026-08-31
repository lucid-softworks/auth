use crate::{AuthPlugin, PluginClientMetadata, PluginDescriptor, PluginEndpoint, PluginHttpMethod};
use async_trait::async_trait;
use std::{borrow::Cow, fmt};

#[cfg(feature = "axum")]
mod axum;

const ENDPOINTS: &[PluginEndpoint] = &[PluginEndpoint {
    method: PluginHttpMethod::Get,
    path: Cow::Borrowed("/expo-authorization-proxy"),
    client_method: "expoAuthorizationProxy",
}];
const NON_ACTION_PATHS: &[&str] = &["/expo-authorization-proxy"];
const CLIENT_ACTIONS: &[&str] = &["getCookie"];
const DEVELOPMENT_ORIGINS: &[&str] = &["exp://"];

/// Exact server options published by `@better-auth/expo@1.7.2`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExpoOptions {
    pub disable_origin_override: bool,
}

/// Native server equivalent of `@better-auth/expo@1.7.2`'s `expo()` plugin.
#[derive(Clone, Copy, Default)]
pub struct ExpoPlugin {
    options: ExpoOptions,
}

impl ExpoPlugin {
    pub const fn new(options: ExpoOptions) -> Self {
        Self { options }
    }

    pub const fn options(&self) -> &ExpoOptions {
        &self.options
    }
}

impl fmt::Debug for ExpoPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpoPlugin")
            .field("options", &self.options)
            .finish()
    }
}

#[async_trait]
impl AuthPlugin for ExpoPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "expo",
            display_name: "Better Auth Expo",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::pinned_upstream(
                "@better-auth/expo",
                crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
                "@better-auth/expo",
                "expo",
            ),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Borrowed(ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(
                PluginClientMetadata::official(
                    "@better-auth/expo",
                    "@better-auth/expo/client",
                    "expoClient",
                )
                .with_identity("expo", "1.7.2")
                .with_custom_actions(CLIENT_ACTIONS)
                .with_non_action_paths(NON_ACTION_PATHS),
            ),
        }
    }

    fn trusted_origins(&self) -> Cow<'static, [&'static str]> {
        development_origins(std::env::var("NODE_ENV").ok().as_deref())
    }

    fn open_api_endpoints(&self) -> Vec<crate::OpenApiEndpoint> {
        Vec::new()
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: std::sync::Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service)
    }

    #[cfg(feature = "axum")]
    async fn on_request(
        &self,
        _service: &crate::AuthService,
        request: ::axum::extract::Request,
    ) -> Result<::axum::extract::Request, ::axum::response::Response> {
        Ok(axum::bridge_origin(&self.options, request))
    }

    #[cfg(feature = "axum")]
    fn contributes_on_request(&self) -> bool {
        true
    }

    #[cfg(feature = "axum")]
    async fn after_response(
        &self,
        service: &crate::AuthService,
        request: &crate::PluginRequestContext,
        response: ::axum::response::Response,
    ) -> ::axum::response::Response {
        axum::handoff_redirect_cookie(service, request, response)
    }

    #[cfg(feature = "axum")]
    fn contributes_on_response(&self) -> bool {
        true
    }
}

fn development_origins(environment: Option<&str>) -> Cow<'static, [&'static str]> {
    if environment == Some("development") {
        Cow::Borrowed(DEVELOPMENT_ORIGINS)
    } else {
        Cow::Borrowed(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_matches_the_published_server_and_client_boundaries() {
        let plugin = ExpoPlugin::default();
        let descriptor = plugin.descriptor();
        assert_eq!(descriptor.id, "expo");
        assert_eq!(descriptor.endpoints, ENDPOINTS);
        assert!(descriptor.cookies.is_empty());
        assert!(descriptor.rate_limits.is_empty());
        assert!(descriptor.middleware.is_empty());
        let client = descriptor.client.unwrap();
        assert_eq!(client.import_path, "@better-auth/expo/client");
        assert_eq!(client.factory, "expoClient");
        assert_eq!(client.custom_actions, CLIENT_ACTIONS);
        assert_eq!(client.non_action_paths, NON_ACTION_PATHS);
        let crate::PluginProvenance::PinnedBetterAuthPort { server, .. } = descriptor.provenance
        else {
            panic!("Expo must remain a pinned Better Auth port");
        };
        assert_eq!(server.package, "@better-auth/expo");
        assert_eq!(server.export, "expo");
        assert!(plugin.open_api_endpoints().is_empty());
    }

    #[test]
    fn initialization_adds_only_the_exact_development_origin() {
        assert_eq!(
            development_origins(Some("development")).as_ref(),
            ["exp://"]
        );
        assert!(development_origins(Some("production")).is_empty());
        assert!(development_origins(None).is_empty());
    }
}
