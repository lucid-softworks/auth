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
pub(crate) enum DodoCall {
    ListCustomers(DodoCustomerListRequest),
    CreateCustomer(DodoCustomerCreateRequest, Option<String>),
    UpdateCustomer(String, DodoCustomerUpdateRequest),
    Portal(String),
    RetrieveProduct(String),
    CheckoutSession(Value),
    Payment(Value),
    ListPayments(DodoPaymentListRequest),
    Subscription(Value),
    ListSubscriptions(DodoSubscriptionListRequest),
    IngestUsage(DodoUsageIngestRequest),
    ListUsage(DodoUsageListRequest),
}

#[derive(Default)]
pub(crate) struct FakeDodoClient {
    calls: Mutex<Vec<DodoCall>>,
}

impl FakeDodoClient {
    pub(crate) async fn calls(&self) -> Vec<DodoCall> {
        self.calls.lock().await.clone()
    }

    async fn record(&self, call: DodoCall) {
        self.calls.lock().await.push(call);
    }
}

#[async_trait]
impl DodoPaymentsClient for FakeDodoClient {
    fn environment(&self) -> DodoPaymentsEnvironment {
        DodoPaymentsEnvironment::Test
    }

    async fn list_customers(
        &self,
        request: DodoCustomerListRequest,
    ) -> Result<DodoCustomerPage, DodoPaymentsProviderError> {
        self.record(DodoCall::ListCustomers(request)).await;
        Ok(DodoCustomerPage {
            items: vec![DodoCustomer {
                customer_id: "cus_contract".into(),
                value: json!({"customer_id": "cus_contract"}),
            }],
            value: json!({"items": [{"customer_id": "cus_contract"}]}),
        })
    }

    async fn create_customer(
        &self,
        request: DodoCustomerCreateRequest,
        idempotency_key: Option<&str>,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError> {
        self.record(DodoCall::CreateCustomer(
            request,
            idempotency_key.map(str::to_owned),
        ))
        .await;
        Ok(DodoCustomer {
            customer_id: "cus_created".into(),
            value: json!({"customer_id": "cus_created"}),
        })
    }

    async fn update_customer(
        &self,
        customer_id: &str,
        request: DodoCustomerUpdateRequest,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError> {
        self.record(DodoCall::UpdateCustomer(customer_id.into(), request))
            .await;
        Ok(DodoCustomer {
            customer_id: customer_id.into(),
            value: json!({"customer_id": customer_id}),
        })
    }

    async fn retrieve_product(
        &self,
        product_id: &str,
    ) -> Result<DodoProviderProduct, DodoPaymentsProviderError> {
        self.record(DodoCall::RetrieveProduct(product_id.into()))
            .await;
        Ok(DodoProviderProduct {
            is_recurring: false,
            value: json!({"product_id": product_id, "is_recurring": false}),
        })
    }

    async fn list_payments(
        &self,
        request: DodoPaymentListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
        self.record(DodoCall::ListPayments(request)).await;
        Ok(DodoProviderItemPage {
            items: vec![json!({"payment_id": "pay_contract"})],
            value: json!({"items": [{"payment_id": "pay_contract"}]}),
        })
    }

    async fn list_subscriptions(
        &self,
        request: DodoSubscriptionListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
        self.record(DodoCall::ListSubscriptions(request)).await;
        Ok(DodoProviderItemPage {
            items: vec![json!({"subscription_id": "sub_contract"})],
            value: json!({"items": [{"subscription_id": "sub_contract"}]}),
        })
    }

    async fn ingest_usage(
        &self,
        request: DodoUsageIngestRequest,
    ) -> Result<DodoUsageIngestResult, DodoPaymentsProviderError> {
        self.record(DodoCall::IngestUsage(request)).await;
        Ok(DodoUsageIngestResult {
            ingested_count: 1,
            value: json!({"ingested_count": 1}),
        })
    }

    async fn list_usage(
        &self,
        request: DodoUsageListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
        self.record(DodoCall::ListUsage(request)).await;
        Ok(DodoProviderItemPage {
            items: vec![json!({"meter_id": "meter_contract"})],
            value: json!({"items": [{"meter_id": "meter_contract"}]}),
        })
    }

    async fn create_customer_portal(
        &self,
        customer_id: &str,
    ) -> Result<DodoCustomerPortal, DodoPaymentsProviderError> {
        self.record(DodoCall::Portal(customer_id.into())).await;
        Ok(DodoCustomerPortal {
            link: "https://portal.dodo.test/customer".into(),
            value: json!({"link": "https://portal.dodo.test/customer"}),
        })
    }

    async fn create_checkout_session(
        &self,
        request: Value,
    ) -> Result<DodoCheckoutSession, DodoPaymentsProviderError> {
        self.record(DodoCall::CheckoutSession(request)).await;
        Ok(DodoCheckoutSession {
            session_id: "checkout_session_contract".into(),
            checkout_url: Some("https://checkout.dodo.test/session".into()),
            client_secret: None,
            payment_id: None,
            publishable_key: None,
            value: json!({
                "session_id": "checkout_session_contract",
                "checkout_url": "https://checkout.dodo.test/session"
            }),
        })
    }

    async fn create_payment(
        &self,
        request: Value,
    ) -> Result<DodoPaymentOrSubscription, DodoPaymentsProviderError> {
        self.record(DodoCall::Payment(request)).await;
        Ok(DodoPaymentOrSubscription {
            payment_link: Some("https://checkout.dodo.test/payment".into()),
            value: json!({"payment_link": "https://checkout.dodo.test/payment"}),
        })
    }

    async fn create_subscription(
        &self,
        request: Value,
    ) -> Result<DodoPaymentOrSubscription, DodoPaymentsProviderError> {
        self.record(DodoCall::Subscription(request)).await;
        Ok(DodoPaymentOrSubscription {
            payment_link: Some("https://checkout.dodo.test/subscription".into()),
            value: json!({"payment_link": "https://checkout.dodo.test/subscription"}),
        })
    }
}
