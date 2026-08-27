use crate::*;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub(super) struct TestStripeClient {
    pub customer: Mutex<Option<StripeCustomer>>,
    pub subscriptions: Mutex<Vec<StripeSubscription>>,
    pub customer_updates: Mutex<Vec<Value>>,
    pub subscription_updates: Mutex<Vec<Value>>,
}

impl TestStripeClient {
    pub(super) fn new() -> Self {
        Self {
            customer: Mutex::new(None),
            subscriptions: Mutex::new(Vec::new()),
            customer_updates: Mutex::new(Vec::new()),
            subscription_updates: Mutex::new(Vec::new()),
        }
    }
}

pub(super) fn organization() -> Organization {
    Organization {
        id: Uuid::new_v4().to_string(),
        name: "New name".into(),
        slug: "new-name".into(),
        logo: None,
        metadata: None,
        created_at: Utc::now(),
    }
}

pub(super) fn provider_subscription(status: SubscriptionStatus) -> StripeSubscription {
    StripeSubscription {
        id: "sub_1".into(),
        customer: serde_json::json!("cus_org"),
        status,
        items: StripeSubscriptionItemList {
            data: vec![StripeSubscriptionItem {
                id: "si_seat".into(),
                price: StripePrice {
                    id: "price_seat".into(),
                    active: true,
                    lookup_key: None,
                    recurring: None,
                    extra: Default::default(),
                },
                quantity: Some(1.0),
                current_period_start: 1,
                current_period_end: 2,
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

pub(super) fn plugin(
    client: Arc<TestStripeClient>,
    store: Arc<MemoryStripeStore>,
    subscriptions: bool,
) -> StripePlugin {
    let mut options = StripeOptions::new(client, "whsec_test");
    options.organization = Some(OrganizationOptions {
        get_customer_create_params: None,
        on_customer_create: None,
    });
    if subscriptions {
        let plan = StripePlan {
            name: "Team".into(),
            price_id: Some("price_base".into()),
            lookup_key: None,
            annual_discount_price_id: None,
            annual_discount_lookup_key: None,
            limits: None,
            group: None,
            seat_price_id: Some("price_seat".into()),
            proration_behavior: ProrationBehavior::None,
            line_items: vec![],
            free_trial: None,
        };
        options.subscription = SubscriptionConfiguration::Enabled(SubscriptionOptions::new(
            Arc::new(StaticPlans(vec![plan])),
        ));
    }
    StripePlugin::new(options, store)
}

fn unused<T>() -> Result<T, StripeProviderError> {
    Err(StripeProviderError::transport("unused test method"))
}

#[async_trait]
impl StripeClient for TestStripeClient {
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
        self.customer
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| StripeProviderError::transport("missing test customer"))
    }

    async fn update_customer(
        &self,
        _: &str,
        params: Value,
    ) -> Result<StripeCustomer, StripeProviderError> {
        self.customer_updates.lock().unwrap().push(params);
        self.retrieve_customer("").await
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
        Ok(StripePage {
            data: self.subscriptions.lock().unwrap().clone(),
            has_more: false,
            url: None,
        })
    }

    async fn retrieve_subscription(
        &self,
        id: &str,
    ) -> Result<StripeSubscription, StripeProviderError> {
        self.subscriptions
            .lock()
            .unwrap()
            .iter()
            .find(|subscription| subscription.id == id)
            .cloned()
            .ok_or_else(|| StripeProviderError::transport("missing test subscription"))
    }

    async fn update_subscription(
        &self,
        id: &str,
        params: Value,
    ) -> Result<StripeSubscription, StripeProviderError> {
        self.subscription_updates.lock().unwrap().push(params);
        self.retrieve_subscription(id).await
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
        _: &[u8],
        _: &str,
        _: &str,
    ) -> Result<StripeEvent, StripeProviderError> {
        unused()
    }
}
