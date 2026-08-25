use async_trait::async_trait;
use lucid_auth::{
    CommetClient, CommetCustomerCreate, CommetCustomerUpdate, CommetProviderError,
    CommetSeatMutation, CommetSeatSetAll, CommetSubscriptionCancel, CommetUsageEvent,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tokio::sync::Mutex;

const PORTAL_URL: &str = concat!("https:", "/", "/portal.commet.test/session");

#[derive(Default)]
pub(crate) struct ProjectionClient {
    responses: Mutex<BTreeMap<&'static str, Value>>,
    cancellation_ids: Mutex<Vec<String>>,
}

impl ProjectionClient {
    pub(crate) async fn respond(&self, operation: &'static str, response: Value) {
        self.responses.lock().await.insert(operation, response);
    }

    pub(crate) async fn cancellation_ids(&self) -> Vec<String> {
        self.cancellation_ids.lock().await.clone()
    }

    async fn response(&self, operation: &'static str, default: Value) -> Value {
        self.responses
            .lock()
            .await
            .get(operation)
            .cloned()
            .unwrap_or(default)
    }
}

#[async_trait]
impl CommetClient for ProjectionClient {
    async fn list_customers(&self, _external_id: &str) -> Result<Value, CommetProviderError> {
        Ok(json!({"data": []}))
    }

    async fn create_customer(
        &self,
        _request: CommetCustomerCreate,
    ) -> Result<Value, CommetProviderError> {
        Ok(json!({}))
    }

    async fn update_customer(
        &self,
        _customer_id: &str,
        _request: CommetCustomerUpdate,
    ) -> Result<Value, CommetProviderError> {
        Ok(json!({}))
    }

    async fn create_portal_session(
        &self,
        _customer_id: &str,
    ) -> Result<Value, CommetProviderError> {
        Ok(self
            .response("portal", json!({"portalUrl": PORTAL_URL}))
            .await)
    }

    async fn get_active_subscription(
        &self,
        _customer_id: &str,
    ) -> Result<Value, CommetProviderError> {
        Ok(self
            .response("subscription", json!({"id": "sub_projection"}))
            .await)
    }

    async fn cancel_subscription(
        &self,
        subscription_id: &str,
        _request: CommetSubscriptionCancel,
    ) -> Result<Value, CommetProviderError> {
        self.cancellation_ids
            .lock()
            .await
            .push(subscription_id.into());
        Ok(json!({"id": subscription_id}))
    }

    async fn list_feature_access(&self, _customer_id: &str) -> Result<Value, CommetProviderError> {
        Ok(self
            .response("features", json!({"data": [{"code": "reports"}]}))
            .await)
    }

    async fn get_feature_access(
        &self,
        _customer_id: &str,
        _code: &str,
    ) -> Result<Value, CommetProviderError> {
        Ok(json!({}))
    }

    async fn check_usage(
        &self,
        _customer_id: &str,
        _feature_code: &str,
    ) -> Result<Value, CommetProviderError> {
        Ok(json!({}))
    }

    async fn create_usage_event(
        &self,
        _request: CommetUsageEvent,
        _idempotency_key: Option<&str>,
    ) -> Result<Value, CommetProviderError> {
        Ok(json!({}))
    }

    async fn list_seat_balances(&self, _customer_id: &str) -> Result<Value, CommetProviderError> {
        Ok(self
            .response("seat_balances", json!({"balances": {"members": 1}}))
            .await)
    }

    async fn add_seats(&self, _request: CommetSeatMutation) -> Result<Value, CommetProviderError> {
        Ok(json!({}))
    }

    async fn remove_seats(
        &self,
        _request: CommetSeatMutation,
    ) -> Result<Value, CommetProviderError> {
        Ok(json!({}))
    }

    async fn set_seats(&self, _request: CommetSeatMutation) -> Result<Value, CommetProviderError> {
        Ok(json!({}))
    }

    async fn set_all_seats(
        &self,
        _request: CommetSeatSetAll,
    ) -> Result<Value, CommetProviderError> {
        Ok(self.response("set_all_seats", json!({"data": []})).await)
    }
}
