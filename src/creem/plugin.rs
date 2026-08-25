use super::{
    CREEM_ADAPTER_VERSION, CreemOptions, CreemStore, MemoryCreemStore, metadata::endpoints,
};
use crate::{
    AuthConfig, AuthError, AuthPlugin, AuthStore, PluginClientMetadata, PluginDescriptor,
    PluginMigration, PluginSchemaField,
};
use std::{borrow::Cow, fmt, sync::Arc};

#[derive(Clone)]
pub struct CreemPlugin {
    pub(crate) options: Arc<CreemOptions>,
    pub(crate) store: Arc<dyn CreemStore>,
}

impl CreemPlugin {
    pub fn new(options: CreemOptions, store: Arc<dyn CreemStore>) -> Self {
        if options.api_key.is_empty() {
            tracing::warn!(
                "[creem] API key is not set. The plugin will initialize, but API functionality will not work until an API key is provided."
            );
        }
        Self {
            options: Arc::new(options),
            store,
        }
    }

    pub fn in_memory(options: CreemOptions, auth_store: Arc<dyn AuthStore>) -> Self {
        Self::new(options, Arc::new(MemoryCreemStore::new(auth_store)))
    }

    pub fn options(&self) -> &CreemOptions {
        &self.options
    }

    pub fn store(&self) -> &Arc<dyn CreemStore> {
        &self.store
    }
}

impl fmt::Debug for CreemPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreemPlugin")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AuthPlugin for CreemPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "creem",
            display_name: "Creem",
            version: CREEM_ADAPTER_VERSION,
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Owned(endpoints(self.options.webhook_enabled())),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(
                PluginClientMetadata::current(
                    "@creem_io/better-auth",
                    "@creem_io/better-auth/client",
                    "creemClient",
                )
                .with_identity("creem", CREEM_ADAPTER_VERSION)
                .with_non_action_paths(&["/creem/webhook"]),
            ),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        super::schema::migration(&self.options.schema, self.options.persist_subscriptions)
            .map(|_| ())
            .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))
    }

    fn migrations(&self) -> Cow<'_, [PluginMigration]> {
        let migration =
            super::schema::migration(&self.options.schema, self.options.persist_subscriptions)
                .expect("Creem schema was validated during plugin registry construction");
        if migration.sql.is_empty() {
            Cow::Borrowed(&[])
        } else {
            Cow::Owned(vec![migration])
        }
    }

    fn schema_fields(&self) -> Vec<PluginSchemaField> {
        super::schema::user_schema_fields(&self.options.schema, self.options.persist_subscriptions)
            .expect("Creem schema was validated during plugin registry construction")
    }

    fn request_security(
        &self,
        method: crate::PluginHttpMethod,
        path: &str,
    ) -> crate::PluginRequestSecurity {
        if self.options.webhook_enabled()
            && method == crate::PluginHttpMethod::Post
            && path == "/creem/webhook"
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
        if method == crate::PluginHttpMethod::Post && path == "/creem/create-checkout" {
            &["successUrl"]
        } else {
            &[]
        }
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        super::axum::routes(service, self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryStore, PluginHttpMethod, PluginRequestSecurity};

    fn plugin(options: CreemOptions) -> CreemPlugin {
        CreemPlugin::in_memory(options, Arc::new(MemoryStore::default()))
    }

    #[test]
    fn descriptor_has_exact_client_and_conditional_webhook_surface() {
        let disabled = plugin(CreemOptions::new("key")).descriptor();
        assert_eq!(disabled.id, "creem");
        assert_eq!(disabled.endpoints.len(), 6);
        let client = disabled.client.unwrap();
        assert_eq!(client.package, "@creem_io/better-auth");
        assert_eq!(client.import_path, "@creem_io/better-auth/client");
        assert_eq!(client.factory, "creemClient");
        assert_eq!(client.client_id, Some("creem"));

        let mut options = CreemOptions::new("key");
        options.webhook_secret = Some("secret".into());
        let enabled = plugin(options);
        assert_eq!(enabled.descriptor().endpoints.len(), 7);
        assert_eq!(
            enabled.request_security(PluginHttpMethod::Post, "/creem/webhook"),
            PluginRequestSecurity::RawPublic
        );
    }

    #[test]
    fn persistence_controls_schema_and_rejects_disabled_remapping() {
        let enabled = plugin(CreemOptions::new("key"));
        assert_eq!(enabled.schema_fields().len(), 2);
        assert_eq!(enabled.migrations().len(), 1);

        let mut options = CreemOptions::new("key");
        options.persist_subscriptions = false;
        let disabled = plugin(options.clone());
        assert!(disabled.schema_fields().is_empty());
        assert!(disabled.migrations().is_empty());

        options.schema.model_mut("user");
        let invalid = plugin(options);
        assert!(
            invalid
                .validate(&AuthConfig::new([42; 32]).unwrap())
                .is_err()
        );
    }
}
