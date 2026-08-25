use super::{POLAR_ADAPTER_VERSION, PolarOptions, metadata::descriptor_endpoints};
use crate::{
    AuthConfig, AuthError, AuthPlugin, DatabaseHooks, PluginClientMetadata, PluginDescriptor,
};
use std::{borrow::Cow, fmt, sync::Arc};

#[derive(Clone)]
pub struct PolarPlugin {
    pub(crate) options: Arc<PolarOptions>,
}

impl PolarPlugin {
    pub fn new(options: PolarOptions) -> Self {
        Self {
            options: Arc::new(options),
        }
    }

    pub fn options(&self) -> &PolarOptions {
        &self.options
    }
}

impl fmt::Debug for PolarPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolarPlugin")
            .field("options", &self.options)
            .finish()
    }
}

#[async_trait::async_trait]
impl AuthPlugin for PolarPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "polar",
            display_name: "Polar",
            version: POLAR_ADAPTER_VERSION,
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Owned(descriptor_endpoints(&self.options)),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(
                PluginClientMetadata::current(
                    "@polar-sh/better-auth",
                    "@polar-sh/better-auth/client",
                    "polarClient",
                )
                .with_identity("polar-client", POLAR_ADAPTER_VERSION)
                .with_custom_actions(&["checkoutEmbed"])
                .with_non_action_paths(&["/polar/webhooks"]),
            ),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        Ok(())
    }

    fn database_hooks(&self) -> Option<&dyn DatabaseHooks> {
        Some(self)
    }

    fn request_security(
        &self,
        method: crate::PluginHttpMethod,
        path: &str,
    ) -> crate::PluginRequestSecurity {
        if self.options.webhooks().is_some()
            && method == crate::PluginHttpMethod::Post
            && path == "/polar/webhooks"
        {
            crate::PluginRequestSecurity::RawPublic
        } else {
            crate::PluginRequestSecurity::Browser
        }
    }

    fn request_origin_fields(
        &self,
        method: crate::PluginHttpMethod,
        path: &str,
    ) -> &'static [&'static str] {
        if self.options.checkout().is_some()
            && method == crate::PluginHttpMethod::Post
            && path == "/checkout"
        {
            &["successUrl", "returnUrl"]
        } else {
            &[]
        }
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        let state = super::axum::PolarRouteState::from_plugin(self);
        super::axum::routes(service, state)
    }
}
