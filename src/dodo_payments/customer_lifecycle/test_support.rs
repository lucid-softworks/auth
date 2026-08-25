use crate::{
    AuthStore, AuthUser, DatabaseHookContext, DatabaseHookRequest, DodoCheckoutSession,
    DodoCustomer, DodoCustomerCreateRequest, DodoCustomerListRequest, DodoCustomerPage,
    DodoCustomerParamsProvider, DodoCustomerPortal, DodoCustomerUpdateRequest,
    DodoPaymentListRequest, DodoPaymentOrSubscription, DodoPaymentsClient, DodoPaymentsEnvironment,
    DodoPaymentsOptions, DodoPaymentsPlugin, DodoPaymentsProviderError, DodoProviderItemPage,
    DodoProviderProduct, DodoSubscriptionListRequest, DodoUsageIngestRequest,
    DodoUsageIngestResult, DodoUsageListRequest, MemoryStore,
};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Default)]
pub(super) struct FakeCustomerClient {
    pub customers: Mutex<Vec<DodoCustomer>>,
    pub calls: Mutex<Vec<String>>,
    pub create_requests: Mutex<Vec<DodoCustomerCreateRequest>>,
    pub update_requests: Mutex<Vec<DodoCustomerUpdateRequest>>,
    pub idempotency_keys: Mutex<Vec<String>>,
    pub error: Mutex<Option<String>>,
}

impl FakeCustomerClient {
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn fail(&self) -> Result<(), DodoPaymentsProviderError> {
        match self.error.lock().unwrap().clone() {
            Some(error) => Err(DodoPaymentsProviderError::new(error)),
            None => Ok(()),
        }
    }
}

#[async_trait]
impl DodoPaymentsClient for FakeCustomerClient {
    fn environment(&self) -> DodoPaymentsEnvironment {
        DodoPaymentsEnvironment::Test
    }

    async fn list_customers(
        &self,
        _request: DodoCustomerListRequest,
    ) -> Result<DodoCustomerPage, DodoPaymentsProviderError> {
        self.calls.lock().unwrap().push("list".into());
        self.fail()?;
        Ok(DodoCustomerPage {
            items: self.customers.lock().unwrap().clone(),
            value: json!({}),
        })
    }

    async fn create_customer(
        &self,
        request: DodoCustomerCreateRequest,
        idempotency_key: Option<&str>,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError> {
        self.calls.lock().unwrap().push("create".into());
        self.create_requests.lock().unwrap().push(request.clone());
        self.idempotency_keys
            .lock()
            .unwrap()
            .push(idempotency_key.unwrap_or_default().into());
        self.fail()?;
        Ok(DodoCustomer {
            customer_id: format!("customer_{}", request.email),
            value: json!({}),
        })
    }

    async fn update_customer(
        &self,
        customer_id: &str,
        request: DodoCustomerUpdateRequest,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("update:{customer_id}"));
        self.update_requests.lock().unwrap().push(request);
        self.fail()?;
        Ok(DodoCustomer {
            customer_id: customer_id.into(),
            value: json!({}),
        })
    }

    async fn create_customer_portal(
        &self,
        _customer_id: &str,
    ) -> Result<DodoCustomerPortal, DodoPaymentsProviderError> {
        Err(DodoPaymentsProviderError::new("unused test operation"))
    }

    async fn retrieve_product(
        &self,
        _product_id: &str,
    ) -> Result<DodoProviderProduct, DodoPaymentsProviderError> {
        Err(DodoPaymentsProviderError::new("unused test operation"))
    }

    async fn create_checkout_session(
        &self,
        _request: Value,
    ) -> Result<DodoCheckoutSession, DodoPaymentsProviderError> {
        Err(DodoPaymentsProviderError::new("unused test operation"))
    }

    async fn create_payment(
        &self,
        _request: Value,
    ) -> Result<DodoPaymentOrSubscription, DodoPaymentsProviderError> {
        Err(DodoPaymentsProviderError::new("unused test operation"))
    }

    async fn list_payments(
        &self,
        _request: DodoPaymentListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
        Err(DodoPaymentsProviderError::new("unused test operation"))
    }

    async fn create_subscription(
        &self,
        _request: Value,
    ) -> Result<DodoPaymentOrSubscription, DodoPaymentsProviderError> {
        Err(DodoPaymentsProviderError::new("unused test operation"))
    }

    async fn list_subscriptions(
        &self,
        _request: DodoSubscriptionListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
        Err(DodoPaymentsProviderError::new("unused test operation"))
    }

    async fn ingest_usage(
        &self,
        _request: DodoUsageIngestRequest,
    ) -> Result<DodoUsageIngestResult, DodoPaymentsProviderError> {
        Err(DodoPaymentsProviderError::new("unused test operation"))
    }

    async fn list_usage(
        &self,
        _request: DodoUsageListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
        Err(DodoPaymentsProviderError::new("unused test operation"))
    }
}

pub(super) async fn plugin(client: Arc<FakeCustomerClient>) -> (DodoPaymentsPlugin, AuthUser) {
    plugin_with_options(client, true, None).await
}

pub(super) async fn plugin_with_options(
    client: Arc<FakeCustomerClient>,
    enabled: bool,
    get_customer_params: Option<Arc<dyn DodoCustomerParamsProvider>>,
) -> (DodoPaymentsPlugin, AuthUser) {
    let store = Arc::new(MemoryStore::default());
    let user = user();
    store
        .create_user_without_account(user.clone())
        .await
        .unwrap();
    let mut options = DodoPaymentsOptions::new(client, Vec::new());
    options.create_customer_on_sign_up = enabled;
    options.get_customer_params = get_customer_params;
    (DodoPaymentsPlugin::new(options, store), user)
}

pub(super) fn user() -> AuthUser {
    let now = Utc::now();
    AuthUser {
        id: Uuid::new_v4(),
        username: None,
        display_username: None,
        name: "Ada".into(),
        email: "ada@example.com".into(),
        email_verified: true,
        image: None,
        additional_fields: Map::new(),
        role: "user".into(),
        is_anonymous: false,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        created_at: now,
        updated_at: now,
    }
}

pub(super) fn context() -> DatabaseHookContext {
    DatabaseHookContext {
        request: Some(DatabaseHookRequest {
            method: "POST".into(),
            path: "/sign-up/email".into(),
            query: None,
            headers: Default::default(),
        }),
        creation_method: None,
    }
}
