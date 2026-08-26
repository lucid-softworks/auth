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

use crate::{
    AdditionalField, AdditionalFieldType, AuthPlugin, PluginClientMetadata, PluginDescriptor,
    PluginEndpoint, PluginHttpMethod, PluginSchemaTable,
};
use std::sync::Arc;

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
            provenance: crate::PluginProvenance::better_auth_plugin("username"),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::official(
                "better-auth",
                "better-auth/client/plugins",
                "usernameClient",
            )),
        }
    }

    fn schema(&self) -> Vec<PluginSchemaTable> {
        let config = self.config.clone();
        let username_config = config.clone();
        let username = AdditionalField::new(AdditionalFieldType::String)
            .optional()
            .sortable(true)
            .unique(true)
            .transform_input(Arc::new(move |value: serde_json::Value| {
                let Some(value) = value.as_str() else {
                    return Ok(value);
                };
                let normalized = if !username_config.normalize_username {
                    value.to_owned()
                } else if let Some(normalizer) = &username_config.username_normalizer {
                    normalizer.normalize(value)
                } else {
                    value.to_lowercase()
                };
                Ok(serde_json::Value::String(normalized))
            }));
        let mut table = PluginSchemaTable::new("user").field("username", username);
        if config.display_username {
            table = table.field(
                "displayUsername",
                AdditionalField::new(AdditionalFieldType::String)
                    .optional()
                    .transform_input(Arc::new(move |value: serde_json::Value| {
                        let Some(value) = value.as_str() else {
                            return Ok(value);
                        };
                        Ok(serde_json::Value::String(
                            config.display_username_normalizer.as_ref().map_or_else(
                                || value.to_owned(),
                                |normalizer| normalizer.normalize(value),
                            ),
                        ))
                    })),
            );
        }
        vec![crate::database_schema::remap_plugin_table(
            table,
            &self.config.schema,
            false,
        )]
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: std::sync::Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        http::routes(service)
    }
}
