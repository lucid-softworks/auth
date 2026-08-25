use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, CheckoutOptions, PolarCheckout, PolarCheckoutCreate, PolarClient, PolarCustomer,
    PolarCustomerCreate, PolarCustomerList, PolarCustomerSession, PolarCustomerSessionCreate,
    PolarCustomerUpdate, PolarCustomerUpdateExternal, PolarEventIngest, PolarEventsIngest,
    PolarFeature, PolarOptions, PolarOrderQuery, PolarPageQuery, PolarPlugin,
    PolarProduct, PolarProducts, PolarProviderError, PolarReferenceSubscriptionQuery,
    PolarSubscriptionQuery, PolarTheme, PortalOptions, UsageOptions, WebhooksOptions,
};
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Debug)]
struct ConformancePolar;

pub(super) fn register(config: &mut AuthConfig) {
    let checkout = CheckoutOptions {
        products: Some(PolarProducts::static_products(vec![PolarProduct {
            product_id: "product_native".into(),
            slug: "native".into(),
        }])),
        theme: Some(PolarTheme::Dark),
        ..CheckoutOptions::default()
    };
    let portal = PortalOptions::new(
        Some("https://app.example.test/account%20home"),
        Some(PolarTheme::Light),
    )
    .expect("absolute Polar portal return URL");
    let options = PolarOptions::new(
        Arc::new(ConformancePolar),
        vec![
            PolarFeature::Checkout(checkout),
            PolarFeature::Portal(portal),
            PolarFeature::Usage(UsageOptions::default()),
            PolarFeature::Webhooks(WebhooksOptions::new("native-webhook-secret")),
        ],
    );
    config
        .add_plugin(PolarPlugin::new(options))
        .expect("unique Polar plugin");
}

#[async_trait]
impl PolarClient for ConformancePolar {
    async fn create_checkout(
        &self,
        request: PolarCheckoutCreate,
    ) -> Result<PolarCheckout, PolarProviderError> {
        let value = json!({
            "url": "https://polar.example.test/checkout?source=native",
            "products": request.products,
            "externalCustomerId": request.external_customer_id,
            "metadata": request.metadata,
        });
        Ok(PolarCheckout {
            url: value["url"].as_str().expect("checkout URL").into(),
            value,
        })
    }

    async fn list_customers(&self, _email: &str) -> Result<PolarCustomerList, PolarProviderError> {
        Ok(PolarCustomerList {
            items: Vec::new(),
            value: page(Vec::new()),
        })
    }

    async fn create_customer(
        &self,
        _request: PolarCustomerCreate,
    ) -> Result<PolarCustomer, PolarProviderError> {
        Ok(customer())
    }

    async fn update_customer(
        &self,
        _id: &str,
        _request: PolarCustomerUpdate,
    ) -> Result<PolarCustomer, PolarProviderError> {
        Ok(customer())
    }

    async fn update_customer_external(
        &self,
        _external_id: &str,
        _request: PolarCustomerUpdateExternal,
    ) -> Result<PolarCustomer, PolarProviderError> {
        Ok(customer())
    }

    async fn delete_customer(&self, _id: &str) -> Result<(), PolarProviderError> {
        Ok(())
    }

    async fn customer_state_external(
        &self,
        external_id: &str,
    ) -> Result<Value, PolarProviderError> {
        Ok(json!({ "id": external_id, "activeSubscriptions": [] }))
    }

    async fn create_customer_session(
        &self,
        request: PolarCustomerSessionCreate,
    ) -> Result<PolarCustomerSession, PolarProviderError> {
        let value = json!({
            "token": "customer_session_native",
            "customerPortalUrl": "https://polar.example.test/portal?theme=dark",
            "externalCustomerId": request.external_customer_id,
            "returnUrl": request.return_url,
        });
        Ok(PolarCustomerSession {
            token: value["token"].as_str().expect("customer session token").into(),
            customer_portal_url: value["customerPortalUrl"]
                .as_str()
                .expect("customer portal URL")
                .into(),
            value,
        })
    }

    async fn list_benefits(
        &self,
        _customer_session: &str,
        _query: PolarPageQuery,
    ) -> Result<Value, PolarProviderError> {
        Ok(page(vec![json!({ "id": "benefit_native" })]))
    }

    async fn list_customer_subscriptions(
        &self,
        _customer_session: &str,
        _query: PolarSubscriptionQuery,
    ) -> Result<Value, PolarProviderError> {
        Ok(page(vec![json!({ "id": "subscription_customer" })]))
    }

    async fn list_orders(
        &self,
        _customer_session: &str,
        _query: PolarOrderQuery,
    ) -> Result<Value, PolarProviderError> {
        Ok(page(vec![json!({ "id": "order_native" })]))
    }

    async fn list_meters(
        &self,
        _customer_session: &str,
        _query: PolarPageQuery,
    ) -> Result<Value, PolarProviderError> {
        Ok(page(vec![json!({ "id": "meter_native" })]))
    }

    async fn list_subscriptions_by_reference(
        &self,
        query: PolarReferenceSubscriptionQuery,
    ) -> Result<Value, PolarProviderError> {
        Ok(page(vec![json!({
            "id": "subscription_reference",
            "referenceId": query.reference_id,
        })]))
    }

    async fn ingest_events(
        &self,
        request: PolarEventsIngest,
    ) -> Result<Value, PolarProviderError> {
        let PolarEventIngest {
            name,
            metadata,
            external_customer_id,
        } = request.events.into_iter().next().expect("one ingested event");
        Ok(json!({
            "inserted": 1,
            "event": name,
            "metadata": metadata,
            "externalCustomerId": external_customer_id,
        }))
    }
}

fn customer() -> PolarCustomer {
    PolarCustomer {
        id: "customer_native".into(),
        external_id: None,
        value: json!({ "id": "customer_native" }),
    }
}

fn page(items: Vec<Value>) -> Value {
    json!({
        "result": {
            "items": items,
            "pagination": { "totalCount": 1, "maxPage": 1 },
        }
    })
}
