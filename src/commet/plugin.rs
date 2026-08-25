use super::{COMMET_ADAPTER_VERSION, CommetOptions, metadata::descriptor_endpoints};
use crate::{
    AuthConfig, AuthError, AuthPlugin, DatabaseHooks, PluginClientMetadata, PluginDescriptor,
};
use std::{borrow::Cow, fmt, sync::Arc};

/// Native `@commet/better-auth@8.1.0` plugin.
#[derive(Clone)]
pub struct CommetPlugin {
    pub(crate) options: Arc<CommetOptions>,
}

impl CommetPlugin {
    pub fn new(options: CommetOptions) -> Self {
        Self {
            options: Arc::new(options),
        }
    }

    pub fn options(&self) -> &CommetOptions {
        &self.options
    }
}

impl fmt::Debug for CommetPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommetPlugin")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AuthPlugin for CommetPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "commet",
            display_name: "Commet",
            version: COMMET_ADAPTER_VERSION,
            provenance: crate::PluginProvenance::pinned_upstream(
                "@commet/better-auth",
                COMMET_ADAPTER_VERSION,
                "@commet/better-auth",
                "commet",
            ),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Owned(descriptor_endpoints(&self.options.features)),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(
                PluginClientMetadata::official(
                    "@commet/better-auth",
                    "@commet/better-auth/client",
                    "commetClient",
                )
                .with_identity("commet-client", COMMET_ADAPTER_VERSION)
                .with_custom_actions(&["customer.portal"])
                .with_non_action_paths(&["/commet/webhooks"]),
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
            && path == "/commet/webhooks"
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
        CommetFeature, CommetHttpClient, CommetPortalOptions, CommetProviderConfig,
        CommetSubscriptionsOptions, CommetWebhooksOptions, PluginHttpMethod, PluginRequestSecurity,
    };

    fn plugin(features: Vec<CommetFeature>) -> CommetPlugin {
        CommetPlugin::new(CommetOptions::new(
            Arc::new(CommetHttpClient::new(
                CommetProviderConfig::new("ck_commet_sensitive").unwrap(),
            )),
            features,
        ))
    }

    #[test]
    fn descriptor_empty_runtime_and_absent_storage_match_8_1_0() {
        let plugin = plugin(Vec::new());
        let descriptor = plugin.descriptor();
        assert_eq!(descriptor.id, "commet");
        assert!(descriptor.endpoints.is_empty());
        assert!(descriptor.cookies.is_empty());
        assert!(descriptor.rate_limits.is_empty());
        assert!(plugin.schema_fields().is_empty());
        assert!(plugin.migrations().is_empty());
        let client = descriptor.client.expect("Commet has an official client");
        assert_eq!(client.package, "@commet/better-auth");
        assert_eq!(client.import_path, "@commet/better-auth/client");
        assert_eq!(client.factory, "commetClient");
        assert_eq!(client.client_id, Some("commet-client"));
        assert_eq!(client.custom_actions, ["customer.portal"]);
        assert_eq!(client.non_action_paths, ["/commet/webhooks"]);
        assert!(!format!("{plugin:?}").contains("commet_sensitive"));
    }

    #[test]
    fn selection_order_is_stable_and_duplicate_configuration_is_later_wins() {
        let plugin = plugin(vec![
            CommetFeature::Seats,
            CommetFeature::Portal(CommetPortalOptions {
                return_url: Some("https://first.example".into()),
            }),
            CommetFeature::Subscriptions(CommetSubscriptionsOptions::default()),
            CommetFeature::Portal(CommetPortalOptions {
                return_url: Some("https://last.example".into()),
            }),
        ]);
        let descriptor = plugin.descriptor();
        let paths = descriptor
            .endpoints
            .iter()
            .map(|endpoint| endpoint.path.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(paths[0], "/commet/seats");
        assert_eq!(paths[5], "/commet/portal");
        assert_eq!(paths[6], "/commet/subscription");
        assert_eq!(
            plugin
                .options()
                .portal()
                .and_then(|value| value.return_url.as_deref()),
            Some("https://last.example")
        );
    }

    #[test]
    fn only_selected_webhook_is_raw_public() {
        let disabled = plugin(Vec::new());
        assert_eq!(
            disabled.request_security(PluginHttpMethod::Post, "/commet/webhooks"),
            PluginRequestSecurity::Browser
        );
        let enabled = plugin(vec![CommetFeature::Webhooks(CommetWebhooksOptions::new(
            "webhook_sensitive",
        ))]);
        assert_eq!(
            enabled.request_security(PluginHttpMethod::Post, "/commet/webhooks"),
            PluginRequestSecurity::RawPublic
        );
        assert!(!format!("{enabled:?}").contains("webhook_sensitive"));
    }
}
