mod http;
mod normalize;
mod types;

pub use http::PolarHttpClient;
pub use normalize::{PolarPageItemKind, PolarResponseKind, normalize_sdk_value};
pub use types::*;

use async_trait::async_trait;

/// Narrow in-process boundary covering only the Polar calls made by
/// `@polar-sh/better-auth@1.8.4`.
#[async_trait]
pub trait PolarClient: Send + Sync {
    async fn create_checkout(
        &self,
        request: PolarCheckoutCreate,
    ) -> Result<PolarCheckout, PolarProviderError>;

    async fn list_customers(&self, email: &str) -> Result<PolarCustomerList, PolarProviderError>;
    async fn create_customer(
        &self,
        request: PolarCustomerCreate,
    ) -> Result<PolarCustomer, PolarProviderError>;
    async fn update_customer(
        &self,
        id: &str,
        request: PolarCustomerUpdate,
    ) -> Result<PolarCustomer, PolarProviderError>;
    async fn update_customer_external(
        &self,
        external_id: &str,
        request: PolarCustomerUpdateExternal,
    ) -> Result<PolarCustomer, PolarProviderError>;
    async fn delete_customer(&self, id: &str) -> Result<(), PolarProviderError>;
    async fn customer_state_external(
        &self,
        external_id: &str,
    ) -> Result<serde_json::Value, PolarProviderError>;

    async fn create_customer_session(
        &self,
        request: PolarCustomerSessionCreate,
    ) -> Result<PolarCustomerSession, PolarProviderError>;
    async fn list_benefits(
        &self,
        customer_session: &str,
        query: PolarPageQuery,
    ) -> Result<serde_json::Value, PolarProviderError>;
    async fn list_customer_subscriptions(
        &self,
        customer_session: &str,
        query: PolarSubscriptionQuery,
    ) -> Result<serde_json::Value, PolarProviderError>;
    async fn list_orders(
        &self,
        customer_session: &str,
        query: PolarOrderQuery,
    ) -> Result<serde_json::Value, PolarProviderError>;
    async fn list_meters(
        &self,
        customer_session: &str,
        query: PolarPageQuery,
    ) -> Result<serde_json::Value, PolarProviderError>;
    async fn list_subscriptions_by_reference(
        &self,
        query: PolarReferenceSubscriptionQuery,
    ) -> Result<serde_json::Value, PolarProviderError>;
    async fn ingest_events(
        &self,
        request: PolarEventsIngest,
    ) -> Result<serde_json::Value, PolarProviderError>;
}
