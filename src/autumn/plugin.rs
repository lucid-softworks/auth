use super::{AUTUMN_ADAPTER_VERSION, AutumnOptions, metadata::ENDPOINTS};
use crate::{AuthConfig, AuthError, AuthPlugin, PluginDescriptor};
use std::{borrow::Cow, fmt, sync::Arc};

#[derive(Clone)]
pub struct AutumnPlugin {
    pub(crate) options: Arc<AutumnOptions>,
}

impl AutumnPlugin {
    pub fn new(options: AutumnOptions) -> Self {
        Self {
            options: Arc::new(options),
        }
    }

    pub fn options(&self) -> &AutumnOptions {
        &self.options
    }
}

impl Default for AutumnPlugin {
    fn default() -> Self {
        Self::new(AutumnOptions::default())
    }
}

impl fmt::Debug for AutumnPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AutumnPlugin")
            .field("options", &self.options)
            .finish()
    }
}

#[async_trait::async_trait]
impl AuthPlugin for AutumnPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "autumn",
            display_name: "Autumn",
            version: AUTUMN_ADAPTER_VERSION,
            provenance: crate::PluginProvenance::pinned_upstream(
                "autumn-js",
                AUTUMN_ADAPTER_VERSION,
                "autumn-js/better-auth",
                "autumn",
            ),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Borrowed(ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        Ok(())
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        super::axum::routes(service, super::axum::AutumnRouteState::from_plugin(self))
    }
}
