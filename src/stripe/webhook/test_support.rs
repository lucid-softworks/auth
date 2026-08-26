use crate::stripe::*;
use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub(super) struct FakeStripeClient {
    pub event: StripeEvent,
    pub subscription: Mutex<Option<StripeSubscription>>,
    pub construction: Mutex<Option<(Vec<u8>, String, String)>>,
}

impl FakeStripeClient {
    pub fn new(event: StripeEvent) -> Self {
        Self {
            event,
            subscription: Mutex::new(None),
            construction: Mutex::new(None),
        }
    }

    pub fn with_subscription(event: StripeEvent, subscription: StripeSubscription) -> Self {
        let client = Self::new(event);
        *client.subscription.lock().unwrap() = Some(subscription);
        client
    }
}

#[async_trait]
impl StripeClient for FakeStripeClient {
    async fn create_customer(&self, _: Value) -> Result<StripeCustomer, StripeProviderError> {
        unused()
    }
    async fn search_customers(
        &self,
        _: Value,
    ) -> Result<StripePage<StripeCustomer>, StripeProviderError> {
        unused()
    }
    async fn list_customers(
        &self,
        _: Value,
    ) -> Result<StripePage<StripeCustomer>, StripeProviderError> {
        unused()
    }
    async fn retrieve_customer(&self, _: &str) -> Result<StripeCustomer, StripeProviderError> {
        unused()
    }
    async fn update_customer(
        &self,
        _: &str,
        _: Value,
    ) -> Result<StripeCustomer, StripeProviderError> {
        unused()
    }
    async fn list_prices(&self, _: Value) -> Result<StripePage<StripePrice>, StripeProviderError> {
        unused()
    }
    async fn retrieve_price(&self, _: &str) -> Result<StripePrice, StripeProviderError> {
        unused()
    }
    async fn create_checkout_session(
        &self,
        _: Value,
        _: Option<StripeRequestOptions>,
    ) -> Result<StripeCheckoutSession, StripeProviderError> {
        unused()
    }
    async fn retrieve_checkout_session(
        &self,
        _: &str,
    ) -> Result<StripeCheckoutSession, StripeProviderError> {
        unused()
    }
    async fn list_subscriptions(
        &self,
        _: Value,
    ) -> Result<StripePage<StripeSubscription>, StripeProviderError> {
        unused()
    }

    async fn retrieve_subscription(
        &self,
        _id: &str,
    ) -> Result<StripeSubscription, StripeProviderError> {
        self.subscription
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| StripeProviderError::transport("missing fake subscription"))
    }

    async fn update_subscription(
        &self,
        _: &str,
        _: Value,
    ) -> Result<StripeSubscription, StripeProviderError> {
        unused()
    }
    async fn list_subscription_schedules(
        &self,
        _: Value,
    ) -> Result<StripePage<StripeSubscriptionSchedule>, StripeProviderError> {
        unused()
    }
    async fn create_subscription_schedule(
        &self,
        _: Value,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError> {
        unused()
    }
    async fn retrieve_subscription_schedule(
        &self,
        _: &str,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError> {
        unused()
    }
    async fn update_subscription_schedule(
        &self,
        _: &str,
        _: Value,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError> {
        unused()
    }
    async fn release_subscription_schedule(
        &self,
        _: &str,
    ) -> Result<StripeSubscriptionSchedule, StripeProviderError> {
        unused()
    }
    async fn create_billing_portal_session(
        &self,
        _: Value,
    ) -> Result<StripeBillingPortalSession, StripeProviderError> {
        unused()
    }

    async fn construct_webhook_event(
        &self,
        payload: &[u8],
        signature: &str,
        secret: &str,
    ) -> Result<StripeEvent, StripeProviderError> {
        *self.construction.lock().unwrap() =
            Some((payload.to_vec(), signature.to_owned(), secret.to_owned()));
        Ok(self.event.clone())
    }
}

fn unused<T>() -> Result<T, StripeProviderError> {
    Err(StripeProviderError::transport("unused fake Stripe method"))
}

pub(super) fn event(event_type: &str, object: Value) -> StripeEvent {
    StripeEvent {
        id: "evt_1".into(),
        event_type: event_type.into(),
        data: StripeEventData {
            object,
            extra: Default::default(),
        },
        extra: Default::default(),
    }
}

pub(super) fn plan() -> StripePlan {
    StripePlan {
        name: "Pro".into(),
        price_id: Some("price_pro".into()),
        lookup_key: None,
        annual_discount_price_id: None,
        annual_discount_lookup_key: None,
        limits: None,
        group: None,
        seat_price_id: None,
        proration_behavior: ProrationBehavior::default(),
        line_items: vec![],
        free_trial: None,
    }
}

pub(super) fn provider_subscription(status: SubscriptionStatus) -> StripeSubscription {
    StripeSubscription {
        id: "sub_1".into(),
        customer: json!("cus_1"),
        status,
        items: StripeSubscriptionItemList {
            data: vec![StripeSubscriptionItem {
                id: "si_1".into(),
                price: StripePrice {
                    id: "price_pro".into(),
                    active: true,
                    lookup_key: None,
                    recurring: Some(StripeRecurring {
                        interval: BillingInterval::Month,
                        usage_type: None,
                        extra: Default::default(),
                    }),
                    extra: Default::default(),
                },
                quantity: Some(1.0),
                current_period_start: 100,
                current_period_end: 200,
                extra: Default::default(),
            }],
        },
        schedule: None,
        metadata: Default::default(),
        trial_start: None,
        trial_end: None,
        cancel_at_period_end: false,
        cancel_at: None,
        canceled_at: None,
        ended_at: None,
        cancellation_details: None,
        extra: Default::default(),
    }
}

pub(super) fn local_subscription(reference_id: &str) -> Subscription {
    Subscription {
        id: Uuid::new_v4(),
        plan: "pro".into(),
        reference_id: reference_id.into(),
        stripe_customer_id: Some("cus_1".into()),
        stripe_subscription_id: Some("sub_1".into()),
        status: SubscriptionStatus::Active,
        period_start: None,
        period_end: None,
        trial_start: None,
        trial_end: None,
        cancel_at_period_end: false,
        cancel_at: None,
        canceled_at: None,
        ended_at: None,
        seats: Some(1.0),
        billing_interval: Some(BillingInterval::Month),
        stripe_schedule_id: None,
    }
}

pub(super) fn enabled_options(client: Arc<dyn StripeClient>) -> StripeOptions {
    let mut options = StripeOptions::new(client, "whsec_test");
    options.subscription =
        SubscriptionConfiguration::Enabled(SubscriptionOptions::new(Arc::new(StaticPlans(vec![
            plan(),
        ]))));
    options
}
