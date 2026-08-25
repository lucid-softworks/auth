use chrono::Utc;
use lucid_auth::{
    BillingInterval, StripeCheckoutSession, StripeCustomer, StripePage, StripePlan, StripePrice,
    StripeProviderError, StripeRecurring, StripeSchedulePhase, StripeSubscription,
    StripeSubscriptionItem, StripeSubscriptionItemList, StripeSubscriptionSchedule, Subscription,
    SubscriptionStatus,
};
use serde_json::{Map, json};
use std::collections::BTreeMap;
use uuid::Uuid;

pub(super) fn page<T>(data: Vec<T>) -> StripePage<T> {
    StripePage {
        data,
        has_more: false,
        url: None,
    }
}

pub(super) fn customer(id: &str) -> StripeCustomer {
    StripeCustomer {
        id: id.into(),
        deleted: false,
        email: Some("owner@example.com".into()),
        name: Some("Stripe Owner".into()),
        metadata: BTreeMap::new(),
        extra: Map::new(),
    }
}

pub(super) fn price(id: &str) -> StripePrice {
    StripePrice {
        id: id.into(),
        active: true,
        lookup_key: None,
        recurring: Some(StripeRecurring {
            interval: BillingInterval::Month,
            usage_type: None,
            extra: Map::new(),
        }),
        extra: Map::new(),
    }
}

pub(super) fn checkout(id: &str) -> StripeCheckoutSession {
    StripeCheckoutSession {
        id: id.into(),
        url: Some(format!("https://checkout.stripe.test/{id}")),
        mode: Some("subscription".into()),
        subscription: None,
        customer: Some(json!("cus_owner")),
        payment_status: Some("unpaid".into()),
        client_reference_id: None,
        metadata: BTreeMap::new(),
        extra: Map::new(),
    }
}

pub(super) fn plan() -> StripePlan {
    StripePlan {
        name: "Pro".into(),
        price_id: Some("price_pro".into()),
        lookup_key: None,
        annual_discount_price_id: None,
        annual_discount_lookup_key: None,
        limits: Some(BTreeMap::from([("projects".into(), json!(10))])),
        group: None,
        seat_price_id: None,
        proration_behavior: Default::default(),
        line_items: Vec::new(),
        free_trial: None,
    }
}

pub(crate) fn local_subscription(reference_id: String) -> Subscription {
    let now = Utc::now();
    Subscription {
        id: Uuid::new_v4(),
        plan: "pro".into(),
        reference_id,
        stripe_customer_id: Some("cus_owner".into()),
        stripe_subscription_id: Some("sub_active".into()),
        status: SubscriptionStatus::Active,
        period_start: Some(now),
        period_end: Some(now + chrono::Duration::days(30)),
        trial_start: None,
        trial_end: None,
        cancel_at_period_end: true,
        cancel_at: Some(now + chrono::Duration::days(30)),
        canceled_at: None,
        ended_at: None,
        seats: Some(1.0),
        billing_interval: Some(BillingInterval::Month),
        stripe_schedule_id: None,
        created_at: now,
        updated_at: now,
    }
}

pub(crate) fn provider_subscription(id: &str) -> StripeSubscription {
    StripeSubscription {
        id: id.into(),
        customer: json!("cus_owner"),
        status: SubscriptionStatus::Active,
        items: StripeSubscriptionItemList {
            data: vec![StripeSubscriptionItem {
                id: "si_pro".into(),
                price: price("price_pro"),
                quantity: Some(1.0),
                current_period_start: 1_700_000_000,
                current_period_end: 1_702_592_000,
                extra: Map::new(),
            }],
        },
        schedule: None,
        metadata: BTreeMap::new(),
        trial_start: None,
        trial_end: None,
        cancel_at_period_end: true,
        cancel_at: None,
        canceled_at: None,
        ended_at: None,
        cancellation_details: None,
        extra: Map::new(),
    }
}

pub(super) fn schedule(id: &str) -> StripeSubscriptionSchedule {
    StripeSubscriptionSchedule {
        id: id.into(),
        status: "active".into(),
        subscription: Some(json!("sub_active")),
        current_phase: None,
        phases: vec![StripeSchedulePhase {
            start_date: json!(1_700_000_000),
            end_date: Some(json!(1_702_592_000)),
            items: Vec::new(),
            extra: Map::new(),
        }],
        metadata: BTreeMap::new(),
        extra: Map::new(),
    }
}

pub(super) fn resource_missing() -> StripeProviderError {
    StripeProviderError {
        code: Some("resource_missing".into()),
        message: "No such subscription".into(),
        status: Some(404),
    }
}
