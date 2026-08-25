mod http;
mod types;

pub use http::CreemHttpTransport;
pub use types::{CreemProviderConfig, CreemProviderError};

use super::provider::{
    CreemCheckout, CreemCheckoutRequest, CreemPortal, CreemPortalRequest,
    CreemProviderSubscription, CreemTransactionPage, CreemTransactionSearch,
};
use async_trait::async_trait;

/// Narrow in-process boundary for the five Creem SDK calls used by the adapter.
#[async_trait]
pub trait CreemTransport: Send + Sync {
    fn config(&self) -> &CreemProviderConfig;

    async fn create_checkout(
        &self,
        request: CreemCheckoutRequest,
    ) -> Result<CreemCheckout, CreemProviderError>;

    async fn create_portal(
        &self,
        request: CreemPortalRequest,
    ) -> Result<CreemPortal, CreemProviderError>;

    async fn cancel_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<CreemProviderSubscription, CreemProviderError>;

    async fn retrieve_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<CreemProviderSubscription, CreemProviderError>;

    async fn search_transactions(
        &self,
        search: CreemTransactionSearch,
    ) -> Result<CreemTransactionPage, CreemProviderError>;
}
