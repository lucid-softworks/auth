use super::models::{checkout, customer, page, price, resource_missing, schedule};
use async_trait::async_trait;
use lucid_auth::{
    StripeBillingPortalSession, StripeCheckoutSession, StripeClient, StripeCustomer, StripeEvent,
    StripeEventData, StripePage, StripePrice, StripeProviderError, StripeRequestOptions,
    StripeSubscription, StripeSubscriptionSchedule,
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use tokio::sync::Mutex;

#[derive(Default)]
struct FakeState {
    calls: Vec<(String, Value)>,
    subscriptions: BTreeMap<String, StripeSubscription>,
    webhook_request: Option<(Vec<u8>, String, String)>,
}

#[derive(Default)]
pub(crate) struct FakeStripeClient {
    state: Mutex<FakeState>,
}

impl FakeStripeClient {
    pub(crate) async fn insert_subscription(&self, subscription: StripeSubscription) {
        self.state
            .lock()
            .await
            .subscriptions
            .insert(subscription.id.clone(), subscription);
    }

    pub(crate) async fn calls(&self, name: &str) -> Vec<Value> {
        self.state
            .lock()
            .await
            .calls
            .iter()
            .filter_map(|(stored, params)| (stored == name).then_some(params.clone()))
            .collect()
    }

    pub(crate) async fn webhook_request(&self) -> Option<(Vec<u8>, String, String)> {
        self.state.lock().await.webhook_request.clone()
    }
}

#[async_trait]
impl StripeClient for FakeStripeClient {
    async fn create_customer(&self, params: Value) -> Result<StripeCustomer, StripeProviderError> {
        self.record("create_customer", params).await;
        Ok(customer("cus_test"))
    }

    async fn search_customers(
        &self,
        params: Value,
    ) -> Result<StripePage<StripeCustomer>, StripeProviderError> {
        self.record("search_customers", params).await;
        Ok(page(Vec::new()))
    }

    async fn list_customers(
        &self,
        params: Value,
    ) -> Result<StripePage<StripeCustomer>, StripeProviderError> {
        self.record("list_customers", params).await;
        Ok(page(Vec::new()))
    }

    async fn retrieve_customer(&self, id: &str) -> Result<StripeCustomer, StripeProviderError> {
        Ok(customer(id))
    }

    async fn update_customer(
        &self,
        id: &str,
        params: Value,
    ) -> Result<StripeCustomer, StripeProviderError> {
        self.record(&format!("update_customer:{id}"), params).await;
        Ok(customer(id))
    }

    async fn list_prices(
        &self,
        params: Value,
    ) -> Result<StripePage<StripePrice>, StripeProviderError> {
        self.record("list_prices", params).await;
        Ok(page(vec![price("price_pro")]))
    }

    async fn retrieve_price(&self, id: &str) -> Result<StripePrice, StripeProviderError> {
        Ok(price(id))
    }

    async fn create_checkout_session(
        &self,
        params: Value,
        _options: Option<StripeRequestOptions>,
    ) -> Result<StripeCheckoutSession, StripeProviderError> {
        self.record("create_checkout_session", params).await;
        Ok(checkout("cs_created"))
    }

    async fn retrieve_checkout_session(
        &self,
        id: &str,
    ) -> Result<StripeCheckoutSession, StripeProviderError> {
        self.record(&format!("retrieve_checkout_session:{id}"), Value::Null)
            .await;
        Ok(checkout(id))
    }

    async fn list_subscriptions(
        &self,
        params: Value,
    ) -> Result<StripePage<StripeSubscription>, StripeProviderError> {
        let mut state = self.state.lock().await;
        state.calls.push(("list_subscriptions".into(), params));
        Ok(page(state.subscriptions.values().cloned().collect()))
    }

    async fn retrieve_subscription(
        &self,
        id: &str,
    ) -> Result<StripeSubscription, StripeProviderError> {
        self.state
            .lock()
            .await
            .subscriptions
            .get(id)
            .cloned()
            .ok_or_else(resource_missing)
    }

    async fn update_subscription(
        &self,
        id: &str,
        params: Value,
    ) -> Result<StripeSubscription, StripeProviderError> {
        let mut state = self.state.lock().await;
        state
            .calls
            .push((format!("update_subscription:{id}"), params.clone()));
        let subscription = state
            .subscriptions
            .get_mut(id)
            .ok_or_else(resource_missing)?;
        if params.get("cancel_at") == Some(&json!("")) {
            subscription.cancel_at = None;
        }
        if params.get("cancel_at_period_end") == Some(&json!(false)) {
            subscription.cancel_at_period_end = false;
        }
        Ok(subscription.clone())
    }

    async fn list_subscription_schedules(
        &self,
        params: Value,
    ) -> Result<StripePage<StripeSubscriptionSchedule>, StripeProviderError> {
        self.record("list_subscription_schedules", params).await;
        Ok(page(Vec::new()))
    }

    async fn create_subscription_schedule(
        &self,
        params: Value,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError> {
        self.record("create_subscription_schedule", params).await;
        Ok(schedule("sub_sched"))
    }

    async fn retrieve_subscription_schedule(
        &self,
        id: &str,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError> {
        Ok(schedule(id))
    }

    async fn update_subscription_schedule(
        &self,
        id: &str,
        params: Value,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError> {
        self.record(&format!("update_subscription_schedule:{id}"), params)
            .await;
        Ok(schedule(id))
    }

    async fn release_subscription_schedule(
        &self,
        id: &str,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError> {
        self.record(&format!("release_subscription_schedule:{id}"), Value::Null)
            .await;
        Ok(schedule(id))
    }

    async fn create_billing_portal_session(
        &self,
        params: Value,
    ) -> Result<StripeBillingPortalSession, StripeProviderError> {
        self.record("create_billing_portal_session", params).await;
        Ok(StripeBillingPortalSession {
            id: "bps_test".into(),
            url: "https://billing.stripe.test/session".into(),
            extra: Map::new(),
        })
    }

    async fn construct_webhook_event(
        &self,
        payload: &[u8],
        signature: &str,
        secret: &str,
    ) -> Result<StripeEvent, StripeProviderError> {
        self.state.lock().await.webhook_request =
            Some((payload.to_vec(), signature.to_owned(), secret.to_owned()));
        if signature == "bad" {
            return Err(StripeProviderError::transport("invalid signature"));
        }
        Ok(StripeEvent {
            id: "evt_contract".into(),
            event_type: "invoice.paid".into(),
            data: StripeEventData {
                object: json!({}),
                extra: Map::new(),
            },
            extra: Map::new(),
        })
    }
}

impl FakeStripeClient {
    async fn record(&self, name: &str, params: Value) {
        self.state
            .lock()
            .await
            .calls
            .push((name.to_owned(), params));
    }
}
