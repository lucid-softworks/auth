use super::{DODO_PAYMENTS_ADAPTER_VERSION, DodoPaymentsOptions, metadata::descriptor_endpoints};
use crate::{
    AuthConfig, AuthError, AuthPlugin, AuthStore, DatabaseHooks, PluginClientMetadata,
    PluginDescriptor, PluginMigration, PluginSchemaField,
};
use std::{borrow::Cow, fmt, sync::Arc};

/// Native `@dodopayments/better-auth@1.6.5` plugin.
#[derive(Clone)]
pub struct DodoPaymentsPlugin {
    pub(crate) options: Arc<DodoPaymentsOptions>,
    pub(crate) auth_store: Arc<dyn AuthStore>,
}

impl DodoPaymentsPlugin {
    pub fn new(options: DodoPaymentsOptions, auth_store: Arc<dyn AuthStore>) -> Self {
        Self {
            options: Arc::new(options),
            auth_store,
        }
    }

    pub fn options(&self) -> &DodoPaymentsOptions {
        &self.options
    }
}

impl fmt::Debug for DodoPaymentsPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DodoPaymentsPlugin")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AuthPlugin for DodoPaymentsPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "dodopayments",
            display_name: "Dodo Payments",
            version: DODO_PAYMENTS_ADAPTER_VERSION,
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Owned(descriptor_endpoints(&self.options.features)),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(
                PluginClientMetadata::current(
                    "@dodopayments/better-auth",
                    "@dodopayments/better-auth/client",
                    "dodopaymentsClient",
                )
                .with_identity("dodopayments-client", DODO_PAYMENTS_ADAPTER_VERSION)
                .with_non_action_paths(&["/dodopayments/webhooks"]),
            ),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        Ok(())
    }

    fn migrations(&self) -> Cow<'_, [PluginMigration]> {
        super::schema::dodo_payments_migrations()
    }

    fn schema_fields(&self) -> Vec<PluginSchemaField> {
        vec![super::schema::dodo_user_schema_field()]
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
            && path == "/dodopayments/webhooks"
        {
            crate::PluginRequestSecurity::RawPublic
        } else {
            crate::PluginRequestSecurity::Browser
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
    use crate::{
        DodoCheckoutOptions, DodoPaymentsFeature, DodoPaymentsHttpClient,
        DodoPaymentsProviderConfig, DodoWebhooksOptions, MemoryStore, PluginHttpMethod,
        PluginRequestSecurity,
    };

    fn plugin(features: Vec<DodoPaymentsFeature>) -> DodoPaymentsPlugin {
        let client = Arc::new(DodoPaymentsHttpClient::new(
            DodoPaymentsProviderConfig::test("api_sensitive"),
        ));
        DodoPaymentsPlugin::new(
            DodoPaymentsOptions::new(client, features),
            Arc::new(MemoryStore::default()),
        )
    }

    #[test]
    fn descriptor_and_schema_match_the_exact_root_plugin() {
        let plugin = plugin(Vec::new());
        let descriptor = plugin.descriptor();
        assert_eq!(descriptor.id, "dodopayments");
        assert!(descriptor.endpoints.is_empty());
        assert!(descriptor.cookies.is_empty());
        assert!(descriptor.rate_limits.is_empty());
        let client = descriptor.client.unwrap();
        assert_eq!(client.package, "@dodopayments/better-auth");
        assert_eq!(client.import_path, "@dodopayments/better-auth/client");
        assert_eq!(client.factory, "dodopaymentsClient");
        assert_eq!(client.client_id, Some("dodopayments-client"));
        assert_eq!(plugin.schema_fields().len(), 1);
        assert!(plugin.migrations().is_empty());
    }

    #[test]
    fn selected_groups_only_contribute_their_routes() {
        let plugin = plugin(vec![
            DodoPaymentsFeature::Checkout(DodoCheckoutOptions::default()),
            DodoPaymentsFeature::Usage,
        ]);
        let descriptor = plugin.descriptor();
        let paths = descriptor
            .endpoints
            .iter()
            .map(|endpoint| endpoint.path.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            [
                "/dodopayments/checkout",
                "/dodopayments/checkout-session",
                "/dodopayments/usage/ingest",
                "/dodopayments/usage/meters/list",
            ]
        );
    }

    #[test]
    fn only_an_enabled_webhook_route_is_raw_public() {
        let disabled = plugin(Vec::new());
        assert_eq!(
            disabled.request_security(PluginHttpMethod::Post, "/dodopayments/webhooks"),
            PluginRequestSecurity::Browser
        );
        let enabled = plugin(vec![DodoPaymentsFeature::Webhooks(
            DodoWebhooksOptions::new("whsec_sensitive"),
        )]);
        assert_eq!(
            enabled.request_security(PluginHttpMethod::Post, "/dodopayments/webhooks"),
            PluginRequestSecurity::RawPublic
        );
        assert!(!format!("{enabled:?}").contains("whsec_sensitive"));
        assert!(!format!("{enabled:?}").contains("api_sensitive"));
    }
}
