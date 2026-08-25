use async_trait::async_trait;
use lucid_auth::{
    CommetClient, CommetCustomerCreate, CommetCustomerUpdate, CommetProviderError,
    CommetSeatMutation, CommetSeatSetAll, CommetSubscriptionCancel, CommetUsageEvent,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tokio::sync::Mutex;

const PORTAL_URL: &str = concat!("https:", "/", "/portal.commet.test/session?keep=1");

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum CommetCall {
    Portal(String),
    Subscription(String),
    Cancel(String, CommetSubscriptionCancel),
    ListFeatures(String),
    GetFeature(String, String),
    CheckUsage(String, String),
    TrackUsage(CommetUsageEvent, Option<String>),
    ListSeats(String),
    AddSeats(CommetSeatMutation),
    RemoveSeats(CommetSeatMutation),
    SetSeats(CommetSeatMutation),
    SetAllSeats(CommetSeatSetAll),
}

#[derive(Default)]
pub(crate) struct FakeCommetClient {
    calls: Mutex<Vec<CommetCall>>,
    failures: Mutex<BTreeMap<&'static str, CommetProviderError>>,
    responses: Mutex<BTreeMap<&'static str, Value>>,
}

impl FakeCommetClient {
    pub(crate) async fn calls(&self) -> Vec<CommetCall> {
        self.calls.lock().await.clone()
    }

    pub(crate) async fn fail(&self, operation: &'static str, error: CommetProviderError) {
        self.failures.lock().await.insert(operation, error);
    }

    pub(crate) async fn respond(&self, operation: &'static str, value: Value) {
        self.responses.lock().await.insert(operation, value);
    }

    async fn record(&self, call: CommetCall) {
        self.calls.lock().await.push(call);
    }

    async fn result(
        &self,
        operation: &'static str,
        default: Value,
    ) -> Result<Value, CommetProviderError> {
        if let Some(error) = self.failures.lock().await.get(operation).cloned() {
            return Err(error);
        }
        Ok(self
            .responses
            .lock()
            .await
            .get(operation)
            .cloned()
            .unwrap_or(default))
    }
}

#[async_trait]
impl CommetClient for FakeCommetClient {
    async fn list_customers(&self, _external_id: &str) -> Result<Value, CommetProviderError> {
        Ok(json!({"data": []}))
    }

    async fn create_customer(
        &self,
        _request: CommetCustomerCreate,
    ) -> Result<Value, CommetProviderError> {
        Ok(json!({"id": "customer_contract"}))
    }

    async fn update_customer(
        &self,
        _customer_id: &str,
        _request: CommetCustomerUpdate,
    ) -> Result<Value, CommetProviderError> {
        Ok(json!({"id": "customer_contract"}))
    }

    async fn create_portal_session(&self, customer_id: &str) -> Result<Value, CommetProviderError> {
        self.record(CommetCall::Portal(customer_id.into())).await;
        self.result("portal", json!({"portalUrl": PORTAL_URL}))
            .await
    }

    async fn get_active_subscription(
        &self,
        customer_id: &str,
    ) -> Result<Value, CommetProviderError> {
        self.record(CommetCall::Subscription(customer_id.into()))
            .await;
        self.result(
            "subscription",
            json!({"id": "sub_contract", "status": "active"}),
        )
        .await
    }

    async fn cancel_subscription(
        &self,
        subscription_id: &str,
        request: CommetSubscriptionCancel,
    ) -> Result<Value, CommetProviderError> {
        self.record(CommetCall::Cancel(subscription_id.into(), request))
            .await;
        self.result(
            "cancel",
            json!({"id": subscription_id, "status": "canceled"}),
        )
        .await
    }

    async fn list_feature_access(&self, customer_id: &str) -> Result<Value, CommetProviderError> {
        self.record(CommetCall::ListFeatures(customer_id.into()))
            .await;
        self.result(
            "list_features",
            json!({"data": [{"code": "reports"}], "next": "ignored"}),
        )
        .await
    }

    async fn get_feature_access(
        &self,
        customer_id: &str,
        code: &str,
    ) -> Result<Value, CommetProviderError> {
        self.record(CommetCall::GetFeature(customer_id.into(), code.into()))
            .await;
        self.result(
            "get_feature",
            json!({"id": "access_contract", "customerId": customer_id, "code": code}),
        )
        .await
    }

    async fn check_usage(
        &self,
        customer_id: &str,
        feature_code: &str,
    ) -> Result<Value, CommetProviderError> {
        self.record(CommetCall::CheckUsage(
            customer_id.into(),
            feature_code.into(),
        ))
        .await;
        self.result(
            "check_usage",
            json!({"allowed": true, "customerId": customer_id, "featureCode": feature_code}),
        )
        .await
    }

    async fn create_usage_event(
        &self,
        request: CommetUsageEvent,
        idempotency_key: Option<&str>,
    ) -> Result<Value, CommetProviderError> {
        self.record(CommetCall::TrackUsage(
            request,
            idempotency_key.map(str::to_owned),
        ))
        .await;
        self.result("track_usage", json!({"id": "usage_contract"}))
            .await
    }

    async fn list_seat_balances(&self, customer_id: &str) -> Result<Value, CommetProviderError> {
        self.record(CommetCall::ListSeats(customer_id.into())).await;
        self.result(
            "list_seats",
            json!({"balances": {"members": 3}, "ignored": true}),
        )
        .await
    }

    async fn add_seats(&self, request: CommetSeatMutation) -> Result<Value, CommetProviderError> {
        self.record(CommetCall::AddSeats(request)).await;
        self.result("add_seats", json!({"operation": "add"})).await
    }

    async fn remove_seats(
        &self,
        request: CommetSeatMutation,
    ) -> Result<Value, CommetProviderError> {
        self.record(CommetCall::RemoveSeats(request)).await;
        self.result("remove_seats", json!({"operation": "remove"}))
            .await
    }

    async fn set_seats(&self, request: CommetSeatMutation) -> Result<Value, CommetProviderError> {
        self.record(CommetCall::SetSeats(request)).await;
        self.result("set_seats", json!({"operation": "set"})).await
    }

    async fn set_all_seats(&self, request: CommetSeatSetAll) -> Result<Value, CommetProviderError> {
        self.record(CommetCall::SetAllSeats(request)).await;
        self.result(
            "set_all_seats",
            json!({"data": [{"operation": "set-all"}], "ignored": true}),
        )
        .await
    }
}
