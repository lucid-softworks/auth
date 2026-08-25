use async_trait::async_trait;
use lucid_auth::{
    PolarCheckout, PolarCheckoutCreate, PolarClient, PolarCustomer, PolarCustomerCreate,
    PolarCustomerList, PolarCustomerSession, PolarCustomerSessionCreate, PolarCustomerUpdate,
    PolarCustomerUpdateExternal, PolarEventsIngest, PolarOrderQuery, PolarPageQuery,
    PolarProviderError, PolarReferenceSubscriptionQuery, PolarSubscriptionQuery,
};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

#[derive(Default)]
pub(crate) struct FakePolarClient {
    calls: Mutex<Vec<(String, Value)>>,
    fail_next: Mutex<Option<String>>,
}

impl FakePolarClient {
    pub(crate) async fn calls(&self, name: &str) -> Vec<Value> {
        self.calls
            .lock()
            .await
            .iter()
            .filter_map(|(candidate, value)| (candidate == name).then_some(value.clone()))
            .collect()
    }

    pub(crate) async fn fail_next(&self, message: &str) {
        *self.fail_next.lock().await = Some(message.into());
    }

    async fn record<T: Serialize>(&self, name: &str, value: T) -> Result<(), PolarProviderError> {
        self.calls
            .lock()
            .await
            .push((name.into(), serde_json::to_value(value).unwrap()));
        match self.fail_next.lock().await.take() {
            Some(message) => Err(PolarProviderError::new(message)),
            None => Ok(()),
        }
    }
}

#[async_trait]
impl PolarClient for FakePolarClient {
    async fn create_checkout(
        &self,
        request: PolarCheckoutCreate,
    ) -> Result<PolarCheckout, PolarProviderError> {
        self.record("checkout", request).await?;
        Ok(PolarCheckout {
            url: checkout_url().into(),
            value: json!({ "url": checkout_url() }),
        })
    }

    async fn list_customers(&self, email: &str) -> Result<PolarCustomerList, PolarProviderError> {
        self.record("list_customers", email).await?;
        Ok(PolarCustomerList {
            items: Vec::new(),
            value: json!({ "result": { "items": [] } }),
        })
    }

    async fn create_customer(
        &self,
        request: PolarCustomerCreate,
    ) -> Result<PolarCustomer, PolarProviderError> {
        self.record("create_customer", request).await?;
        Ok(customer())
    }

    async fn update_customer(
        &self,
        id: &str,
        request: PolarCustomerUpdate,
    ) -> Result<PolarCustomer, PolarProviderError> {
        self.record(&format!("update_customer:{id}"), request)
            .await?;
        Ok(customer())
    }

    async fn update_customer_external(
        &self,
        external_id: &str,
        request: PolarCustomerUpdateExternal,
    ) -> Result<PolarCustomer, PolarProviderError> {
        self.record(&format!("update_external:{external_id}"), request)
            .await?;
        Ok(customer())
    }

    async fn delete_customer(&self, id: &str) -> Result<(), PolarProviderError> {
        self.record("delete_customer", id).await
    }

    async fn customer_state_external(
        &self,
        external_id: &str,
    ) -> Result<Value, PolarProviderError> {
        self.record("state", external_id).await?;
        Ok(json!({ "id": external_id, "activeSubscriptions": [] }))
    }

    async fn create_customer_session(
        &self,
        request: PolarCustomerSessionCreate,
    ) -> Result<PolarCustomerSession, PolarProviderError> {
        self.record("customer_session", request).await?;
        Ok(PolarCustomerSession {
            token: "portal_token".into(),
            customer_portal_url: portal_url().into(),
            value: json!({}),
        })
    }

    async fn list_benefits(
        &self,
        customer_session: &str,
        query: PolarPageQuery,
    ) -> Result<Value, PolarProviderError> {
        self.record(
            "benefits",
            json!({ "token": customer_session, "query": query }),
        )
        .await?;
        Ok(page("benefit"))
    }

    async fn list_customer_subscriptions(
        &self,
        customer_session: &str,
        query: PolarSubscriptionQuery,
    ) -> Result<Value, PolarProviderError> {
        self.record(
            "customer_subscriptions",
            json!({ "token": customer_session, "query": query }),
        )
        .await?;
        Ok(page("subscription"))
    }

    async fn list_orders(
        &self,
        customer_session: &str,
        query: PolarOrderQuery,
    ) -> Result<Value, PolarProviderError> {
        self.record(
            "orders",
            json!({ "token": customer_session, "query": query }),
        )
        .await?;
        Ok(page("order"))
    }

    async fn list_meters(
        &self,
        customer_session: &str,
        query: PolarPageQuery,
    ) -> Result<Value, PolarProviderError> {
        self.record(
            "meters",
            json!({ "token": customer_session, "query": query }),
        )
        .await?;
        Ok(page("meter"))
    }

    async fn list_subscriptions_by_reference(
        &self,
        query: PolarReferenceSubscriptionQuery,
    ) -> Result<Value, PolarProviderError> {
        self.record(
            "reference_subscriptions",
            json!({
                "referenceId": query.reference_id,
                "page": query.page,
                "limit": query.limit,
                "active": query.active,
            }),
        )
        .await?;
        Ok(page("reference-subscription"))
    }

    async fn ingest_events(&self, request: PolarEventsIngest) -> Result<Value, PolarProviderError> {
        self.record("ingest", request).await?;
        Ok(json!({ "inserted": 1 }))
    }
}

fn customer() -> PolarCustomer {
    PolarCustomer {
        id: "customer_1".into(),
        external_id: Some("user_1".into()),
        value: json!({ "id": "customer_1" }),
    }
}

fn checkout_url() -> &'static str {
    "https://buy.polar.test/session?keep=1"
}

fn portal_url() -> &'static str {
    "https://polar.test/portal?keep=1"
}

fn page(kind: &str) -> Value {
    json!({ "result": { "items": [{ "kind": kind }], "pagination": {} } })
}
