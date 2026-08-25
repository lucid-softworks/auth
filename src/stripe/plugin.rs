use super::{
    StripeOptions, StripeStore, SubscriptionConfiguration, descriptor_endpoints,
    open_api_endpoints, user_schema_field,
};
use crate::{
    AuthConfig, AuthError, AuthPlugin, DatabaseHookContext, DatabaseRecord, PluginClientMetadata,
    PluginDescriptor, PluginMigration, PluginSchemaField,
};
use std::{borrow::Cow, fmt, sync::Arc};

/// Native Better Auth Stripe 1.7.1 plugin.
#[derive(Clone)]
pub struct StripePlugin {
    pub(crate) options: Arc<StripeOptions>,
    pub(crate) store: Arc<dyn StripeStore>,
}

impl StripePlugin {
    pub fn new(options: StripeOptions, store: Arc<dyn StripeStore>) -> Self {
        Self {
            options: Arc::new(options),
            store,
        }
    }

    pub fn options(&self) -> &StripeOptions {
        &self.options
    }

    pub fn subscriptions_enabled(&self) -> bool {
        matches!(
            self.options.subscription,
            SubscriptionConfiguration::Enabled(_)
        )
    }

    pub fn organization_enabled(&self) -> bool {
        self.options.organization.is_some()
    }

    pub(crate) fn initialize_soft_composition(&self, organization_present: bool) {
        if self.organization_enabled() {
            if !organization_present {
                tracing::error!("Organization plugin not found");
            }
            return;
        }
        let SubscriptionConfiguration::Enabled(subscription) = &self.options.subscription else {
            return;
        };
        if let Some(plans) = subscription.plans.static_plans() {
            warn_for_seat_pricing(plans);
            return;
        }
        let plans = subscription.plans.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                match plans.plans().await {
                    Ok(plans) => warn_for_seat_pricing(&plans),
                    Err(error) => tracing::error!(
                        "Failed to resolve plans for seat pricing validation: {}",
                        error.message
                    ),
                }
            });
        }
    }
}

fn warn_for_seat_pricing(plans: &[super::StripePlan]) {
    if plans.iter().any(|plan| plan.seat_price_id.is_some()) {
        tracing::error!(
            "seatPriceId is configured on a plan but stripe organization option is not enabled. Seat-based billing requires `organization: {{ enabled: true }}` in stripe plugin options."
        );
    }
}

impl fmt::Debug for StripePlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StripePlugin")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl AuthPlugin for StripePlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "stripe",
            display_name: "Better Auth Stripe",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::pinned_upstream(
                "@better-auth/stripe",
                crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
                "@better-auth/stripe",
                "stripe",
            ),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Owned(descriptor_endpoints(self.subscriptions_enabled())),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(
                PluginClientMetadata::official(
                    "@better-auth/stripe",
                    "@better-auth/stripe/client",
                    "stripeClient",
                )
                .with_identity("stripe-client", "1.7.1"),
            ),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        super::schema::migration(
            &self.options.schema,
            self.subscriptions_enabled(),
            self.organization_enabled(),
        )
        .map(|_| ())
        .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))
    }

    fn migrations(&self) -> Cow<'_, [PluginMigration]> {
        let migration = super::schema::migration(
            &self.options.schema,
            self.subscriptions_enabled(),
            self.organization_enabled(),
        )
        .expect("Stripe schema was validated during plugin registry construction");
        if migration.sql.is_empty() {
            Cow::Borrowed(&[])
        } else {
            Cow::Owned(vec![migration])
        }
    }

    fn schema_fields(&self) -> Vec<PluginSchemaField> {
        vec![user_schema_field(&self.options.schema)]
    }

    fn open_api_endpoints(&self) -> Vec<crate::OpenApiEndpoint> {
        open_api_endpoints(self.subscriptions_enabled())
    }

    fn request_security(
        &self,
        method: crate::PluginHttpMethod,
        path: &str,
    ) -> crate::PluginRequestSecurity {
        if method == crate::PluginHttpMethod::Post && path == "/stripe/webhook" {
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
        if method == crate::PluginHttpMethod::Post {
            match path {
                "/subscription/upgrade" => &["successUrl", "cancelUrl", "returnUrl"],
                "/subscription/cancel" | "/subscription/billing-portal" => &["returnUrl"],
                _ => &[],
            }
        } else {
            &[]
        }
    }

    async fn after_database_create(
        &self,
        service: &crate::AuthService,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        if self.organization_enabled() && service.organization_plugin().is_err() {
            return Ok(());
        }
        if let DatabaseRecord::User(user) = record {
            super::customer_lifecycle::after_user_create(
                &self.options,
                self.store.as_ref(),
                user,
                context,
            )
            .await;
        }
        Ok(())
    }

    async fn after_database_update(
        &self,
        service: &crate::AuthService,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        if self.organization_enabled() && service.organization_plugin().is_err() {
            return Ok(());
        }
        if let DatabaseRecord::User(user) = record {
            super::customer_lifecycle::after_user_update(
                &self.options,
                self.store.as_ref(),
                user,
                context,
            )
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
    use crate::{
        MemoryStripeStore, PlansProvider, StaticPlans, StripeCallbackError, StripeHttpClient,
        SubscriptionOptions,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct DynamicPlans(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl PlansProvider for DynamicPlans {
        async fn plans(&self) -> Result<Vec<crate::StripePlan>, StripeCallbackError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(StripeCallbackError::new("dynamic failure"))
        }
    }

    #[test]
    fn literal_plan_providers_expose_the_synchronous_init_path() {
        let plans = StaticPlans(Vec::new());
        assert!(
            plans
                .static_plans()
                .is_some_and(<[crate::StripePlan]>::is_empty)
        );
    }

    #[tokio::test]
    async fn dynamic_plan_validation_is_started_at_init() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut options = StripeOptions::new(Arc::new(StripeHttpClient::new("sk_test")), "secret");
        options.subscription = SubscriptionConfiguration::Enabled(SubscriptionOptions::new(
            Arc::new(DynamicPlans(calls.clone())),
        ));
        StripePlugin::new(options, Arc::new(MemoryStripeStore::new()))
            .initialize_soft_composition(false);
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn organization_init_branch_does_not_run_seat_validation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut options = StripeOptions::new(Arc::new(StripeHttpClient::new("sk_test")), "secret");
        options.subscription = SubscriptionConfiguration::Enabled(SubscriptionOptions::new(
            Arc::new(DynamicPlans(calls.clone())),
        ));
        options.organization = Some(crate::OrganizationOptions {
            get_customer_create_params: None,
            on_customer_create: None,
        });
        StripePlugin::new(options, Arc::new(MemoryStripeStore::new()))
            .initialize_soft_composition(false);
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
