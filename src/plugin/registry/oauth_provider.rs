use super::{AuthPlugin, PluginRegistry};
use crate::AuthError;
use std::sync::Arc;

impl PluginRegistry {
    pub(crate) fn oauth_provider(&self) -> Option<&crate::OAuthProviderPlugin> {
        find(&self.plugins)
    }
}

pub(super) fn validate_extensions(plugins: &[Arc<dyn AuthPlugin>]) -> Result<(), AuthError> {
    let Some(provider) = find(plugins) else {
        return Ok(());
    };
    let mut effective = provider.config().clone();
    effective.extensions.extend(
        plugins
            .iter()
            .flat_map(|plugin| plugin.oauth_provider_extensions()),
    );
    effective.validate().map_err(|error| {
        AuthError::InvalidConfiguration(format!(
            "OAuth Provider companion extension configuration is invalid: {error}"
        ))
    })
}

fn find(plugins: &[Arc<dyn AuthPlugin>]) -> Option<&crate::OAuthProviderPlugin> {
    plugins.iter().find_map(|plugin| {
        plugin
            .as_any()
            .downcast_ref::<crate::OAuthProviderPlugin>()
            .or_else(|| {
                plugin
                    .as_any()
                    .downcast_ref::<crate::McpPlugin>()
                    .map(crate::McpPlugin::provider)
            })
    })
}
