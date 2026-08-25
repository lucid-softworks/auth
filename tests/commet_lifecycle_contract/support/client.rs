use async_trait::async_trait;
use lucid_auth::{
    CommetClient, CommetCustomerCreate, CommetCustomerUpdate, CommetProviderError,
    CommetSeatMutation, CommetSeatSetAll, CommetSubscriptionCancel, CommetUsageEvent,
    PluginApiError,
};
use serde_json::{Value, json};
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Call {
    List(String),
    Create(CommetCustomerCreate),
    Update(String, CommetCustomerUpdate),
}

pub(crate) struct LifecycleClient {
    calls: Mutex<Vec<Call>>,
    customers: Mutex<Value>,
    list_error: Mutex<Option<CommetProviderError>>,
    create_error: Mutex<Option<CommetProviderError>>,
    update_error: Mutex<Option<CommetProviderError>>,
}

impl Default for LifecycleClient {
    fn default() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            customers: Mutex::new(json!({"data": []})),
            list_error: Mutex::new(None),
            create_error: Mutex::new(None),
            update_error: Mutex::new(None),
        }
    }
}

impl LifecycleClient {
    pub(crate) fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    pub(crate) fn set_customers(&self, customers: Value) {
        *self.customers.lock().unwrap() = customers;
    }

    pub(crate) fn fail_list(&self, error: CommetProviderError) {
        *self.list_error.lock().unwrap() = Some(error);
    }

    pub(crate) fn fail_create(&self, error: CommetProviderError) {
        *self.create_error.lock().unwrap() = Some(error);
    }

    pub(crate) fn fail_update(&self, error: CommetProviderError) {
        *self.update_error.lock().unwrap() = Some(error);
    }

    pub(crate) fn api_error(message: &str) -> CommetProviderError {
        CommetProviderError::api(PluginApiError::new(403, "FORBIDDEN", message))
    }

    fn unused() -> CommetProviderError {
        CommetProviderError::new("unexpected lifecycle test operation")
    }
}

#[async_trait]
impl CommetClient for LifecycleClient {
    async fn list_customers(&self, external_id: &str) -> Result<Value, CommetProviderError> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::List(external_id.to_owned()));
        if let Some(error) = self.list_error.lock().unwrap().take() {
            return Err(error);
        }
        Ok(self.customers.lock().unwrap().clone())
    }

    async fn create_customer(
        &self,
        request: CommetCustomerCreate,
    ) -> Result<Value, CommetProviderError> {
        self.calls.lock().unwrap().push(Call::Create(request));
        if let Some(error) = self.create_error.lock().unwrap().take() {
            return Err(error);
        }
        Ok(json!({"id": "customer_created"}))
    }

    async fn update_customer(
        &self,
        customer_id: &str,
        request: CommetCustomerUpdate,
    ) -> Result<Value, CommetProviderError> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Update(customer_id.to_owned(), request));
        if let Some(error) = self.update_error.lock().unwrap().take() {
            return Err(error);
        }
        Ok(json!({"id": customer_id}))
    }

    async fn create_portal_session(
        &self,
        _customer_id: &str,
    ) -> Result<Value, CommetProviderError> {
        Err(Self::unused())
    }

    async fn get_active_subscription(
        &self,
        _customer_id: &str,
    ) -> Result<Value, CommetProviderError> {
        Err(Self::unused())
    }

    async fn cancel_subscription(
        &self,
        _subscription_id: &str,
        _request: CommetSubscriptionCancel,
    ) -> Result<Value, CommetProviderError> {
        Err(Self::unused())
    }

    async fn list_feature_access(&self, _customer_id: &str) -> Result<Value, CommetProviderError> {
        Err(Self::unused())
    }

    async fn get_feature_access(
        &self,
        _customer_id: &str,
        _code: &str,
    ) -> Result<Value, CommetProviderError> {
        Err(Self::unused())
    }

    async fn check_usage(
        &self,
        _customer_id: &str,
        _feature_code: &str,
    ) -> Result<Value, CommetProviderError> {
        Err(Self::unused())
    }

    async fn create_usage_event(
        &self,
        _request: CommetUsageEvent,
        _idempotency_key: Option<&str>,
    ) -> Result<Value, CommetProviderError> {
        Err(Self::unused())
    }

    async fn list_seat_balances(&self, _customer_id: &str) -> Result<Value, CommetProviderError> {
        Err(Self::unused())
    }

    async fn add_seats(&self, _request: CommetSeatMutation) -> Result<Value, CommetProviderError> {
        Err(Self::unused())
    }

    async fn remove_seats(
        &self,
        _request: CommetSeatMutation,
    ) -> Result<Value, CommetProviderError> {
        Err(Self::unused())
    }

    async fn set_seats(&self, _request: CommetSeatMutation) -> Result<Value, CommetProviderError> {
        Err(Self::unused())
    }

    async fn set_all_seats(
        &self,
        _request: CommetSeatSetAll,
    ) -> Result<Value, CommetProviderError> {
        Err(Self::unused())
    }
}
