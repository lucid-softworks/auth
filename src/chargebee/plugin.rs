use super::{
    CHARGEBEE_CLIENT_PATH_METHODS, CHARGEBEE_ENDPOINTS, CHARGEBEE_NON_ACTION_PATHS,
    ChargebeeOptions, ChargebeeStore,
};
use crate::{
    AuthConfig, AuthPlugin, DatabaseHookContext, DatabaseRecord, PluginClientMetadata,
    PluginDescriptor, PluginHttpMethod, PluginMigration, PluginRequestSecurity, PluginSchemaField,
};
use std::{borrow::Cow, fmt, sync::Arc};

#[derive(Clone)]
pub struct ChargebeePlugin {
    pub(crate) options: Arc<ChargebeeOptions>,
    pub(crate) store: Arc<dyn ChargebeeStore>,
}

impl ChargebeePlugin {
    pub fn new(options: ChargebeeOptions, store: Arc<dyn ChargebeeStore>) -> Self {
        Self {
            options: Arc::new(options),
            store,
        }
    }

    pub fn options(&self) -> &ChargebeeOptions {
        &self.options
    }

    pub fn store(&self) -> &dyn ChargebeeStore {
        self.store.as_ref()
    }

    pub fn subscriptions_enabled(&self) -> bool {
        self.options.subscriptions_enabled()
    }

    pub fn organization_enabled(&self) -> bool {
        self.options.organization_enabled()
    }
}

impl fmt::Debug for ChargebeePlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChargebeePlugin")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AuthPlugin for ChargebeePlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "chargebee",
            display_name: "Chargebee Better Auth",
            version: "1.2.0",
            provenance: crate::PluginProvenance::pinned_upstream(
                "@chargebee/better-auth",
                "1.2.0",
                "@chargebee/better-auth",
                "chargebee",
            ),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Borrowed(CHARGEBEE_ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(
                PluginClientMetadata::official(
                    "@chargebee/better-auth",
                    "@chargebee/better-auth/client",
                    "chargebeeClient",
                )
                .with_identity("chargebee-client", "1.2.0")
                .with_non_action_paths(CHARGEBEE_NON_ACTION_PATHS)
                .with_path_methods(CHARGEBEE_CLIENT_PATH_METHODS),
            ),
        }
    }

    fn migrations(&self) -> Cow<'_, [PluginMigration]> {
        Cow::Owned(vec![super::schema::migration(
            self.subscriptions_enabled(),
            self.organization_enabled(),
        )])
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), crate::AuthError> {
        self.options
            .client
            .set_client_identifier("better-auth 1.2.0");
        if self.options.webhook_credentials().is_none() {
            tracing::warn!(
                "Chargebee plugin: webhookUsername and webhookPassword are not configured. The webhook endpoint is unauthenticated and anyone can POST fake events. Set webhookUsername and webhookPassword in your chargebee plugin options."
            );
        }
        Ok(())
    }

    fn schema_fields(&self) -> Vec<PluginSchemaField> {
        super::schema::schema_fields(self.organization_enabled())
    }

    fn open_api_endpoints(&self) -> Vec<crate::OpenApiEndpoint> {
        super::open_api::endpoints()
    }

    fn request_security(&self, method: PluginHttpMethod, path: &str) -> PluginRequestSecurity {
        if method == PluginHttpMethod::Post && path == "/chargebee/webhook" {
            PluginRequestSecurity::RawPublic
        } else {
            PluginRequestSecurity::Browser
        }
    }

    fn request_origin_fields(
        &self,
        method: PluginHttpMethod,
        path: &str,
    ) -> &'static [&'static str] {
        if method == PluginHttpMethod::Get
            && matches!(
                path,
                "/subscription/success" | "/subscription/cancel/callback"
            )
        {
            &["callbackURL"]
        } else {
            &[]
        }
    }

    async fn after_database_create(
        &self,
        _service: &crate::AuthService,
        record: &DatabaseRecord,
        _context: &DatabaseHookContext,
    ) -> Result<(), crate::AuthError> {
        if let DatabaseRecord::User(user) = record {
            super::customer::after_user_create(&self.options, self.store.as_ref(), user).await;
        }
        Ok(())
    }

    async fn after_database_update(
        &self,
        _service: &crate::AuthService,
        record: &DatabaseRecord,
        _context: &DatabaseHookContext,
    ) -> Result<(), crate::AuthError> {
        if let DatabaseRecord::User(user) = record {
            super::customer::after_user_update(&self.options, self.store.as_ref(), user).await;
        }
        Ok(())
    }

    async fn before_database_delete(
        &self,
        _service: &crate::AuthService,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), crate::AuthError> {
        if let DatabaseRecord::User(user) = record {
            super::customer::before_user_delete(&self.options, self.store.as_ref(), user, context)
                .await;
        }
        Ok(())
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        super::axum::routes(service, self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthStore, MemoryStore, chargebee::MemoryChargebeeStore};

    fn plugin() -> ChargebeePlugin {
        let auth: Arc<dyn AuthStore> = Arc::new(MemoryStore::default());
        let store = Arc::new(MemoryChargebeeStore::new(auth));
        ChargebeePlugin::new(
            ChargebeeOptions::new(Arc::new(super::super::test_support::UnavailableClient)),
            store,
        )
    }

    #[test]
    fn descriptor_always_has_all_routes_and_exact_client_metadata() {
        let descriptor = plugin().descriptor();
        assert_eq!(descriptor.id, "chargebee");
        assert_eq!(descriptor.endpoints.len(), 8);
        let client = descriptor.client.unwrap();
        assert_eq!(client.client_version, Some("1.2.0"));
        assert_eq!(client.path_methods, CHARGEBEE_CLIENT_PATH_METHODS);
        assert!(
            descriptor
                .endpoints
                .iter()
                .any(|endpoint| endpoint.client_method == "subscription.cancel.callback")
        );
    }

    #[test]
    fn post_redirects_are_not_validated_before_reference_middleware() {
        let plugin = plugin();
        assert!(
            plugin
                .request_origin_fields(PluginHttpMethod::Post, "/subscription/create")
                .is_empty()
        );
        assert_eq!(
            plugin.request_origin_fields(PluginHttpMethod::Get, "/subscription/cancel/callback"),
            &["callbackURL"]
        );
    }
}
