use async_trait::async_trait;
use lucid_auth::{
    ChargebeeClient, ChargebeeCustomerListRequest, ChargebeeHostedPage, ChargebeePortalSession,
    ChargebeeProviderCustomer, ChargebeeProviderError, ChargebeeProviderSubscription,
    ChargebeeSubscriptionListRequest, ChargebeeWebhookEvent,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ChargebeeCall {
    ListCustomers(ChargebeeCustomerListRequest),
    CreateCustomer(Value),
    UpdateCustomer(String, Value),
    DeleteCustomer(String),
    ListSubscriptions(ChargebeeSubscriptionListRequest),
    RetrieveSubscription(String),
    CancelSubscription(String, bool),
    CheckoutNew(Value),
    CheckoutExisting(Value),
    Portal(Value),
    ParseWebhook(Vec<u8>, Option<String>, Option<(String, String)>),
}

#[derive(Debug, Default)]
pub(crate) struct FakeChargebeeClient {
    calls: Mutex<Vec<ChargebeeCall>>,
    checkout_failure: Mutex<Option<ChargebeeProviderError>>,
    provider_subscriptions: Mutex<Vec<ChargebeeProviderSubscription>>,
}

impl FakeChargebeeClient {
    pub(crate) async fn calls(&self) -> Vec<ChargebeeCall> {
        self.calls.lock().await.clone()
    }

    pub(crate) async fn fail_checkout(&self, error: ChargebeeProviderError) {
        *self.checkout_failure.lock().await = Some(error);
    }

    pub(crate) async fn set_provider_subscriptions(
        &self,
        subscriptions: Vec<ChargebeeProviderSubscription>,
    ) {
        *self.provider_subscriptions.lock().await = subscriptions;
    }

    async fn record(&self, call: ChargebeeCall) -> Result<(), ChargebeeProviderError> {
        self.calls.lock().await.push(call);
        Ok(())
    }
}

#[async_trait]
impl ChargebeeClient for FakeChargebeeClient {
    async fn list_customers(
        &self,
        request: ChargebeeCustomerListRequest,
    ) -> Result<Vec<ChargebeeProviderCustomer>, ChargebeeProviderError> {
        self.record(ChargebeeCall::ListCustomers(request)).await?;
        Ok(Vec::new())
    }

    async fn create_customer(
        &self,
        request: Value,
    ) -> Result<ChargebeeProviderCustomer, ChargebeeProviderError> {
        self.record(ChargebeeCall::CreateCustomer(request.clone()))
            .await?;
        Ok(customer("customer_contract", &request))
    }

    async fn update_customer(
        &self,
        customer_id: &str,
        request: Value,
    ) -> Result<ChargebeeProviderCustomer, ChargebeeProviderError> {
        self.record(ChargebeeCall::UpdateCustomer(
            customer_id.into(),
            request.clone(),
        ))
        .await?;
        Ok(customer(customer_id, &request))
    }

    async fn delete_customer(&self, customer_id: &str) -> Result<(), ChargebeeProviderError> {
        self.record(ChargebeeCall::DeleteCustomer(customer_id.into()))
            .await
    }

    async fn list_subscriptions(
        &self,
        request: ChargebeeSubscriptionListRequest,
    ) -> Result<Vec<ChargebeeProviderSubscription>, ChargebeeProviderError> {
        self.record(ChargebeeCall::ListSubscriptions(request))
            .await?;
        Ok(self.provider_subscriptions.lock().await.clone())
    }

    async fn retrieve_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<ChargebeeProviderSubscription, ChargebeeProviderError> {
        self.record(ChargebeeCall::RetrieveSubscription(subscription_id.into()))
            .await?;
        self.provider_subscriptions
            .lock()
            .await
            .iter()
            .find(|subscription| subscription.id == subscription_id)
            .cloned()
            .ok_or_else(|| ChargebeeProviderError::new("missing provider subscription"))
    }

    async fn cancel_subscription(
        &self,
        subscription_id: &str,
        end_of_term: bool,
    ) -> Result<ChargebeeProviderSubscription, ChargebeeProviderError> {
        self.record(ChargebeeCall::CancelSubscription(
            subscription_id.into(),
            end_of_term,
        ))
        .await?;
        self.retrieve_subscription(subscription_id).await
    }

    async fn checkout_new_for_items(
        &self,
        request: Value,
    ) -> Result<ChargebeeHostedPage, ChargebeeProviderError> {
        self.record(ChargebeeCall::CheckoutNew(request)).await?;
        if let Some(error) = self.checkout_failure.lock().await.take() {
            return Err(error);
        }
        Ok(ChargebeeHostedPage {
            id: Some("hosted_page_contract".into()),
            url: Some("https://chargebee.example.test/checkout/contract".into()),
        })
    }

    async fn checkout_existing_for_items(
        &self,
        request: Value,
    ) -> Result<ChargebeeHostedPage, ChargebeeProviderError> {
        self.record(ChargebeeCall::CheckoutExisting(request))
            .await?;
        Ok(ChargebeeHostedPage {
            id: Some("hosted_page_update".into()),
            url: Some("https://chargebee.example.test/checkout/update".into()),
        })
    }

    async fn create_portal_session(
        &self,
        request: Value,
    ) -> Result<ChargebeePortalSession, ChargebeeProviderError> {
        self.record(ChargebeeCall::Portal(request)).await?;
        Ok(ChargebeePortalSession {
            access_url: "https://chargebee.example.test/portal/contract".into(),
        })
    }

    async fn parse_webhook(
        &self,
        payload: &[u8],
        authorization: Option<&str>,
        credentials: Option<(&str, &str)>,
    ) -> Result<ChargebeeWebhookEvent, ChargebeeProviderError> {
        let credentials = credentials.map(|(user, pass)| (user.into(), pass.into()));
        self.record(ChargebeeCall::ParseWebhook(
            payload.to_vec(),
            authorization.map(str::to_owned),
            credentials.clone(),
        ))
        .await?;
        if credentials.is_some() && authorization != Some("Basic dXNlcjpwYXNz") {
            return Err(ChargebeeProviderError::webhook_authentication(
                "invalid basic credentials",
            ));
        }
        serde_json::from_slice(payload)
            .map_err(|error| ChargebeeProviderError::webhook_payload(error.to_string()))
    }
}

fn customer(id: &str, request: &Value) -> ChargebeeProviderCustomer {
    ChargebeeProviderCustomer {
        id: id.into(),
        email: request
            .get("email")
            .and_then(Value::as_str)
            .map(str::to_owned),
        metadata: request.get("meta_data").cloned(),
        extra: BTreeMap::from([("fixture".into(), json!(true))]),
    }
}

pub(crate) fn shared_client() -> Arc<FakeChargebeeClient> {
    Arc::new(FakeChargebeeClient::default())
}
