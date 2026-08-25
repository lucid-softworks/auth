use super::{
    CheckoutSessionParams, CustomerCreateCallback, CustomerCreateParams, EventCallback,
    OrganizationCustomerCreateCallback, OrganizationCustomerCreateParams, PlansProvider,
    ReferenceAuthorizer, StripeCallbackError, StripeClient, StripePlan, StripeSchema,
    SubscriptionCallbacks,
};
use std::{fmt, sync::Arc};

#[derive(Clone)]
pub struct StripeOptions {
    pub client: Arc<dyn StripeClient>,
    stripe_webhook_secret: Arc<str>,
    pub create_customer_on_sign_up: bool,
    pub get_customer_create_params: Option<Arc<dyn CustomerCreateParams>>,
    pub on_customer_create: Option<Arc<dyn CustomerCreateCallback>>,
    pub subscription: SubscriptionConfiguration,
    pub organization: Option<OrganizationOptions>,
    pub on_event: Option<Arc<dyn EventCallback>>,
    pub schema: StripeSchema,
}

impl StripeOptions {
    pub fn new(client: Arc<dyn StripeClient>, stripe_webhook_secret: impl Into<String>) -> Self {
        Self {
            client,
            stripe_webhook_secret: Arc::from(stripe_webhook_secret.into()),
            create_customer_on_sign_up: false,
            get_customer_create_params: None,
            on_customer_create: None,
            subscription: SubscriptionConfiguration::Disabled,
            organization: None,
            on_event: None,
            schema: StripeSchema::default(),
        }
    }

    pub fn stripe_webhook_secret(&self) -> &str {
        &self.stripe_webhook_secret
    }

    pub async fn plans(&self) -> Result<Vec<StripePlan>, StripeCallbackError> {
        match &self.subscription {
            SubscriptionConfiguration::Disabled => Err(StripeCallbackError::new(
                "Subscriptions are not enabled in the Stripe options.",
            )),
            SubscriptionConfiguration::Enabled(options) => options.plans.plans().await,
        }
    }

    pub async fn plan_by_name(
        &self,
        name: &str,
    ) -> Result<Option<StripePlan>, StripeCallbackError> {
        Ok(self
            .plans()
            .await?
            .into_iter()
            .find(|plan| plan.matches_name(name)))
    }
}

impl fmt::Debug for StripeOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StripeOptions")
            .field("stripe_webhook_secret", &"[REDACTED]")
            .field(
                "create_customer_on_sign_up",
                &self.create_customer_on_sign_up,
            )
            .field(
                "has_get_customer_create_params",
                &self.get_customer_create_params.is_some(),
            )
            .field("has_on_customer_create", &self.on_customer_create.is_some())
            .field("subscription", &self.subscription)
            .field("organization", &self.organization)
            .field("has_on_event", &self.on_event.is_some())
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
pub enum SubscriptionConfiguration {
    #[default]
    Disabled,
    Enabled(SubscriptionOptions),
}

impl fmt::Debug for SubscriptionConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("Disabled"),
            Self::Enabled(options) => formatter.debug_tuple("Enabled").field(options).finish(),
        }
    }
}

#[derive(Clone)]
pub struct SubscriptionOptions {
    pub plans: Arc<dyn PlansProvider>,
    pub require_email_verification: bool,
    pub authorize_reference: Option<Arc<dyn ReferenceAuthorizer>>,
    pub checkout_session_params: Option<Arc<dyn CheckoutSessionParams>>,
    pub callbacks: Option<Arc<dyn SubscriptionCallbacks>>,
}

impl SubscriptionOptions {
    pub fn new(plans: Arc<dyn PlansProvider>) -> Self {
        Self {
            plans,
            require_email_verification: false,
            authorize_reference: None,
            checkout_session_params: None,
            callbacks: None,
        }
    }
}

impl fmt::Debug for SubscriptionOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubscriptionOptions")
            .field(
                "require_email_verification",
                &self.require_email_verification,
            )
            .field(
                "has_authorize_reference",
                &self.authorize_reference.is_some(),
            )
            .field(
                "has_checkout_session_params",
                &self.checkout_session_params.is_some(),
            )
            .field("has_callbacks", &self.callbacks.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct OrganizationOptions {
    pub get_customer_create_params: Option<Arc<dyn OrganizationCustomerCreateParams>>,
    pub on_customer_create: Option<Arc<dyn OrganizationCustomerCreateCallback>>,
}

impl fmt::Debug for OrganizationOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OrganizationOptions")
            .field("enabled", &true)
            .field(
                "has_get_customer_create_params",
                &self.get_customer_create_params.is_some(),
            )
            .field("has_on_customer_create", &self.on_customer_create.is_some())
            .finish()
    }
}
