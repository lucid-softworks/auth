use async_trait::async_trait;
use lucid_auth::{
    DodoCheckoutSession, DodoCustomer, DodoCustomerCreateRequest, DodoCustomerListRequest,
    DodoCustomerPage, DodoCustomerPortal, DodoCustomerUpdateRequest, DodoPaymentListRequest,
    DodoPaymentOrSubscription, DodoPaymentsClient, DodoPaymentsEnvironment,
    DodoPaymentsProviderError, DodoProviderItemPage, DodoProviderProduct,
    DodoSubscriptionListRequest, DodoUsageIngestRequest, DodoUsageIngestResult,
    DodoUsageListRequest,
};
use serde_json::{Value, json};
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum LifecycleCall {
    ListCustomers(DodoCustomerListRequest),
    CreateCustomer(DodoCustomerCreateRequest, Option<String>),
    Portal(String),
    IngestUsage(DodoUsageIngestRequest),
}

pub(crate) struct LifecycleClient {
    customers: Vec<DodoCustomer>,
    calls: Mutex<Vec<LifecycleCall>>,
}

impl LifecycleClient {
    pub(crate) fn new(customer_id: Option<&str>) -> Self {
        Self {
            customers: customer_id
                .map(|customer_id| DodoCustomer {
                    customer_id: customer_id.into(),
                    value: json!({"customer_id": customer_id}),
                })
                .into_iter()
                .collect(),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub(crate) async fn calls(&self) -> Vec<LifecycleCall> {
        self.calls.lock().await.clone()
    }

    async fn record(&self, call: LifecycleCall) {
        self.calls.lock().await.push(call);
    }

    fn unused() -> DodoPaymentsProviderError {
        DodoPaymentsProviderError::new("unused lifecycle test operation")
    }
}

#[async_trait]
impl DodoPaymentsClient for LifecycleClient {
    fn environment(&self) -> DodoPaymentsEnvironment {
        DodoPaymentsEnvironment::Test
    }

    async fn list_customers(
        &self,
        request: DodoCustomerListRequest,
    ) -> Result<DodoCustomerPage, DodoPaymentsProviderError> {
        self.record(LifecycleCall::ListCustomers(request)).await;
        Ok(DodoCustomerPage {
            items: self.customers.clone(),
            value: json!({}),
        })
    }

    async fn create_customer(
        &self,
        request: DodoCustomerCreateRequest,
        idempotency_key: Option<&str>,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError> {
        self.record(LifecycleCall::CreateCustomer(
            request,
            idempotency_key.map(str::to_owned),
        ))
        .await;
        Ok(DodoCustomer {
            customer_id: "customer_lazy_created".into(),
            value: json!({"customer_id": "customer_lazy_created"}),
        })
    }

    async fn update_customer(
        &self,
        _customer_id: &str,
        _request: DodoCustomerUpdateRequest,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError> {
        Err(Self::unused())
    }

    async fn create_customer_portal(
        &self,
        customer_id: &str,
    ) -> Result<DodoCustomerPortal, DodoPaymentsProviderError> {
        self.record(LifecycleCall::Portal(customer_id.into())).await;
        Ok(DodoCustomerPortal {
            link: "https://portal.dodo.test/lazy".into(),
            value: json!({"link": "https://portal.dodo.test/lazy"}),
        })
    }

    async fn retrieve_product(
        &self,
        _product_id: &str,
    ) -> Result<DodoProviderProduct, DodoPaymentsProviderError> {
        Err(Self::unused())
    }

    async fn create_checkout_session(
        &self,
        _request: Value,
    ) -> Result<DodoCheckoutSession, DodoPaymentsProviderError> {
        Err(Self::unused())
    }

    async fn create_payment(
        &self,
        _request: Value,
    ) -> Result<DodoPaymentOrSubscription, DodoPaymentsProviderError> {
        Err(Self::unused())
    }

    async fn list_payments(
        &self,
        _request: DodoPaymentListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
        Err(Self::unused())
    }

    async fn create_subscription(
        &self,
        _request: Value,
    ) -> Result<DodoPaymentOrSubscription, DodoPaymentsProviderError> {
        Err(Self::unused())
    }

    async fn list_subscriptions(
        &self,
        _request: DodoSubscriptionListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
        Err(Self::unused())
    }

    async fn ingest_usage(
        &self,
        request: DodoUsageIngestRequest,
    ) -> Result<DodoUsageIngestResult, DodoPaymentsProviderError> {
        self.record(LifecycleCall::IngestUsage(request)).await;
        Ok(DodoUsageIngestResult {
            ingested_count: 1,
            value: json!({"ingested_count": 1}),
        })
    }

    async fn list_usage(
        &self,
        _request: DodoUsageListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
        Err(Self::unused())
    }
}
