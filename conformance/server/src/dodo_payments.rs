use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, DodoCheckoutOptions, DodoCheckoutSession, DodoCustomer, DodoCustomerCreateRequest,
    DodoCustomerListRequest, DodoCustomerPage, DodoCustomerPortal, DodoCustomerUpdateRequest,
    DodoPaymentListRequest, DodoPaymentOrSubscription, DodoPaymentsClient, DodoPaymentsEnvironment,
    DodoPaymentsFeature, DodoPaymentsOptions, DodoPaymentsPlugin, DodoPaymentsProviderError,
    DodoProduct, DodoProducts, DodoProviderItemPage, DodoProviderProduct,
    DodoSubscriptionListRequest, DodoUsageIngestRequest, DodoUsageIngestResult,
    DodoUsageListRequest, DodoWebhooksOptions, MemoryStore,
};
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Debug)]
struct ConformanceDodoPayments;

pub(super) fn register(config: &mut AuthConfig, auth_store: Arc<MemoryStore>) {
    let checkout = DodoCheckoutOptions {
        products: Some(DodoProducts::static_products(vec![DodoProduct::new(
            "product_native",
            "native",
        )])),
        success_url: Some("https://app.example.test/dodo-complete".into()),
        authenticated_users_only: false,
    };
    let options = DodoPaymentsOptions::new(
        Arc::new(ConformanceDodoPayments),
        vec![
            DodoPaymentsFeature::Checkout(checkout),
            DodoPaymentsFeature::Portal,
            DodoPaymentsFeature::Usage,
            DodoPaymentsFeature::Webhooks(DodoWebhooksOptions::new(
                "whsec_ZG9kby1uYXRpdmUtY29uZm9ybWFuY2U=",
            )),
        ],
    );
    config
        .add_plugin(DodoPaymentsPlugin::new(options, auth_store))
        .expect("unique Dodo Payments plugin");
}

#[async_trait]
impl DodoPaymentsClient for ConformanceDodoPayments {
    fn environment(&self) -> DodoPaymentsEnvironment {
        DodoPaymentsEnvironment::Test
    }

    async fn list_customers(
        &self,
        request: DodoCustomerListRequest,
    ) -> Result<DodoCustomerPage, DodoPaymentsProviderError> {
        assert_eq!(request.email, "luna@example.com");
        let customer = customer();
        Ok(DodoCustomerPage {
            items: vec![customer],
            value: json!({
                "items": [{
                    "customer_id": "customer_native",
                    "email": request.email,
                }],
            }),
        })
    }

    async fn create_customer(
        &self,
        request: DodoCustomerCreateRequest,
        _idempotency_key: Option<&str>,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError> {
        Ok(DodoCustomer {
            customer_id: "customer_native".into(),
            value: json!({
                "customer_id": "customer_native",
                "email": request.email,
                "name": request.name,
            }),
        })
    }

    async fn update_customer(
        &self,
        _customer_id: &str,
        _request: DodoCustomerUpdateRequest,
    ) -> Result<DodoCustomer, DodoPaymentsProviderError> {
        Ok(customer())
    }

    async fn create_customer_portal(
        &self,
        customer_id: &str,
    ) -> Result<DodoCustomerPortal, DodoPaymentsProviderError> {
        assert_eq!(customer_id, "customer_native");
        let link = format!("https://dodo.example.test/portal/{customer_id}");
        Ok(DodoCustomerPortal {
            value: json!({ "link": link }),
            link,
        })
    }

    async fn retrieve_product(
        &self,
        product_id: &str,
    ) -> Result<DodoProviderProduct, DodoPaymentsProviderError> {
        assert_eq!(product_id, "product_native");
        Ok(DodoProviderProduct {
            is_recurring: false,
            value: json!({
                "product_id": product_id,
                "is_recurring": false,
            }),
        })
    }

    async fn create_checkout_session(
        &self,
        request: Value,
    ) -> Result<DodoCheckoutSession, DodoPaymentsProviderError> {
        assert_eq!(
            request,
            json!({
                "metadata": {
                    "campaign": "native",
                    "referenceId": "session-reference",
                },
                "product_cart": [{ "product_id": "product_native", "quantity": 2 }],
                "return_url": "https://app.example.test/dodo-complete",
            })
        );
        Ok(DodoCheckoutSession {
            session_id: "checkout_session_native".into(),
            checkout_url: Some("https://dodo.example.test/checkout/session-native".into()),
            client_secret: None,
            payment_id: None,
            publishable_key: None,
            value: json!({
                "session_id": "checkout_session_native",
                "checkout_url": "https://dodo.example.test/checkout/session-native",
            }),
        })
    }

    async fn create_payment(
        &self,
        request: Value,
    ) -> Result<DodoPaymentOrSubscription, DodoPaymentsProviderError> {
        assert_eq!(
            request,
            json!({
                "billing": {
                    "city": "London",
                    "country": "GB",
                    "state": "London",
                    "street": "1 Native Street",
                    "zipcode": "N1 1AA",
                },
                "customer": {
                    "email": "dodo-checkout@example.com",
                    "name": "Dodo Checkout",
                },
                "metadata": { "referenceId": "metadata-wins", "seats": 3 },
                "payment_link": true,
                "product_cart": [{ "product_id": "product_native", "quantity": 1 }],
                "return_url": "https://app.example.test/dodo-complete",
            })
        );
        Ok(payment_or_subscription(
            "https://dodo.example.test/checkout/payment-native",
            request,
        ))
    }

    async fn list_payments(
        &self,
        request: DodoPaymentListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
        assert_eq!(request.customer_id, "customer_native");
        assert_eq!(request.page_number, Some(0.0));
        assert_eq!(request.page_size, Some(5.0));
        assert_eq!(
            request.status,
            Some(lucid_auth::DodoPaymentStatus::Succeeded)
        );
        Ok(item_page(json!({
            "payment_id": "payment_native",
            "status": "succeeded",
        })))
    }

    async fn create_subscription(
        &self,
        request: Value,
    ) -> Result<DodoPaymentOrSubscription, DodoPaymentsProviderError> {
        Ok(payment_or_subscription(
            "https://dodo.example.test/checkout/subscription-native",
            request,
        ))
    }

    async fn list_subscriptions(
        &self,
        request: DodoSubscriptionListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
        assert_eq!(request.customer_id, "customer_native");
        assert_eq!(request.page_number, Some(1.0));
        assert_eq!(request.page_size, Some(3.0));
        assert_eq!(
            request.status,
            Some(lucid_auth::DodoSubscriptionStatus::Active)
        );
        Ok(item_page(json!({
            "status": "active",
            "subscription_id": "subscription_native",
        })))
    }

    async fn ingest_usage(
        &self,
        request: DodoUsageIngestRequest,
    ) -> Result<DodoUsageIngestResult, DodoPaymentsProviderError> {
        assert_eq!(
            serde_json::to_value(&request).expect("serialize Dodo usage request"),
            json!({
                "events": [{
                    "customer_id": "customer_native",
                    "event_id": "event_native",
                    "event_name": "tokens",
                    "metadata": { "cached": false, "count": 7 },
                    "timestamp": "2026-08-01T10:34:56.000Z",
                }],
            })
        );
        Ok(DodoUsageIngestResult {
            ingested_count: request.events.len() as u64,
            value: json!({ "ingested_count": request.events.len() }),
        })
    }

    async fn list_usage(
        &self,
        request: DodoUsageListRequest,
    ) -> Result<DodoProviderItemPage, DodoPaymentsProviderError> {
        assert_eq!(request.customer_id.as_deref(), Some("customer_native"));
        assert_eq!(request.page_number, Some(4.0));
        assert_eq!(request.page_size, Some(6.0));
        assert_eq!(request.event_name.as_deref(), Some("tokens"));
        assert_eq!(request.meter_id.as_deref(), Some("meter_native"));
        assert_eq!(request.start.as_deref(), Some("2026-08-01"));
        assert_eq!(request.end.as_deref(), Some("2026-08-02"));
        Ok(item_page(json!({
            "event_name": "tokens",
            "meter_id": "meter_native",
        })))
    }
}

fn customer() -> DodoCustomer {
    DodoCustomer {
        customer_id: "customer_native".into(),
        value: json!({ "customer_id": "customer_native" }),
    }
}

fn payment_or_subscription(link: &str, request: Value) -> DodoPaymentOrSubscription {
    DodoPaymentOrSubscription {
        payment_link: Some(link.into()),
        value: json!({ "payment_link": link, "request": request }),
    }
}

fn item_page(item: Value) -> DodoProviderItemPage {
    DodoProviderItemPage {
        items: vec![item.clone()],
        value: json!({ "items": [item] }),
    }
}
