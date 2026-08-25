mod http;
mod signature;
mod types;

pub use http::StripeHttpClient;
pub use types::*;

use async_trait::async_trait;
use serde_json::Value;

/// Narrow in-process Stripe API boundary used by Better Auth Stripe 1.7.1.
#[async_trait]
pub trait StripeClient: Send + Sync {
    async fn create_customer(&self, params: Value) -> Result<StripeCustomer, StripeProviderError>;
    async fn search_customers(
        &self,
        params: Value,
    ) -> Result<StripePage<StripeCustomer>, StripeProviderError>;
    async fn list_customers(
        &self,
        params: Value,
    ) -> Result<StripePage<StripeCustomer>, StripeProviderError>;
    async fn retrieve_customer(&self, id: &str) -> Result<StripeCustomer, StripeProviderError>;
    async fn update_customer(
        &self,
        id: &str,
        params: Value,
    ) -> Result<StripeCustomer, StripeProviderError>;

    async fn list_prices(
        &self,
        params: Value,
    ) -> Result<StripePage<StripePrice>, StripeProviderError>;
    async fn retrieve_price(&self, id: &str) -> Result<StripePrice, StripeProviderError>;

    async fn create_checkout_session(
        &self,
        params: Value,
        options: Option<StripeRequestOptions>,
    ) -> Result<StripeCheckoutSession, StripeProviderError>;
    async fn retrieve_checkout_session(
        &self,
        id: &str,
    ) -> Result<StripeCheckoutSession, StripeProviderError>;

    async fn list_subscriptions(
        &self,
        params: Value,
    ) -> Result<StripePage<StripeSubscription>, StripeProviderError>;
    async fn retrieve_subscription(
        &self,
        id: &str,
    ) -> Result<StripeSubscription, StripeProviderError>;
    async fn update_subscription(
        &self,
        id: &str,
        params: Value,
    ) -> Result<StripeSubscription, StripeProviderError>;

    async fn list_subscription_schedules(
        &self,
        params: Value,
    ) -> Result<StripePage<StripeSubscriptionSchedule>, StripeProviderError>;
    async fn create_subscription_schedule(
        &self,
        params: Value,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError>;
    async fn retrieve_subscription_schedule(
        &self,
        id: &str,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError>;
    async fn update_subscription_schedule(
        &self,
        id: &str,
        params: Value,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError>;
    async fn release_subscription_schedule(
        &self,
        id: &str,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError>;

    async fn create_billing_portal_session(
        &self,
        params: Value,
    ) -> Result<StripeBillingPortalSession, StripeProviderError>;

    async fn construct_webhook_event(
        &self,
        payload: &[u8],
        signature: &str,
        secret: &str,
    ) -> Result<StripeEvent, StripeProviderError>;
}
