use super::*;
use async_trait::async_trait;
use serde_json::Value;

pub(crate) struct UnavailableClient;

#[async_trait]
impl ChargebeeClient for UnavailableClient {
    async fn list_customers(
        &self,
        _: ChargebeeCustomerListRequest,
    ) -> Result<Vec<ChargebeeProviderCustomer>, ChargebeeProviderError> {
        unimplemented!()
    }

    async fn create_customer(
        &self,
        _: Value,
    ) -> Result<ChargebeeProviderCustomer, ChargebeeProviderError> {
        unimplemented!()
    }

    async fn update_customer(
        &self,
        _: &str,
        _: Value,
    ) -> Result<ChargebeeProviderCustomer, ChargebeeProviderError> {
        unimplemented!()
    }

    async fn delete_customer(&self, _: &str) -> Result<(), ChargebeeProviderError> {
        unimplemented!()
    }

    async fn list_subscriptions(
        &self,
        _: ChargebeeSubscriptionListRequest,
    ) -> Result<Vec<ChargebeeProviderSubscription>, ChargebeeProviderError> {
        unimplemented!()
    }

    async fn retrieve_subscription(
        &self,
        _: &str,
    ) -> Result<ChargebeeProviderSubscription, ChargebeeProviderError> {
        unimplemented!()
    }

    async fn cancel_subscription(
        &self,
        _: &str,
        _: bool,
    ) -> Result<ChargebeeProviderSubscription, ChargebeeProviderError> {
        unimplemented!()
    }

    async fn checkout_new_for_items(
        &self,
        _: Value,
    ) -> Result<ChargebeeHostedPage, ChargebeeProviderError> {
        unimplemented!()
    }

    async fn checkout_existing_for_items(
        &self,
        _: Value,
    ) -> Result<ChargebeeHostedPage, ChargebeeProviderError> {
        unimplemented!()
    }

    async fn create_portal_session(
        &self,
        _: Value,
    ) -> Result<ChargebeePortalSession, ChargebeeProviderError> {
        unimplemented!()
    }

    async fn parse_webhook(
        &self,
        _: &[u8],
        _: Option<&str>,
        _: Option<(&str, &str)>,
    ) -> Result<ChargebeeWebhookEvent, ChargebeeProviderError> {
        unimplemented!()
    }
}
