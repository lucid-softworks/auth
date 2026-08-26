use crate::stripe::{StripePlan, StripeSubscription, StripeSubscriptionItem, SubscriptionPatch};
use chrono::{DateTime, Utc};

pub(crate) struct ResolvedPlanItem<'a> {
    pub item: &'a StripeSubscriptionItem,
    pub plan: Option<&'a StripePlan>,
}

pub(crate) fn resolve_plan_item<'a>(
    plans: &'a [StripePlan],
    items: &'a [StripeSubscriptionItem],
) -> Option<ResolvedPlanItem<'a>> {
    let first = items.first()?;
    for item in items {
        let plan = plans.iter().find(|plan| item_matches_plan(item, plan));
        if let Some(plan) = plan {
            return Some(ResolvedPlanItem {
                item,
                plan: Some(plan),
            });
        }
    }
    (items.len() == 1).then_some(ResolvedPlanItem {
        item: first,
        plan: None,
    })
}

pub(crate) fn resolve_quantity(
    subscription: &StripeSubscription,
    plan_item: &StripeSubscriptionItem,
    plan: &StripePlan,
) -> f64 {
    plan.seat_price_id
        .as_deref()
        .and_then(|seat_price_id| {
            subscription
                .items
                .data
                .iter()
                .find(|item| item.price.id == seat_price_id)
        })
        .and_then(|item| item.quantity)
        .or(plan_item.quantity)
        .unwrap_or(1.0)
}

pub(crate) fn lifecycle_patch(
    subscription: &StripeSubscription,
    item: &StripeSubscriptionItem,
    plan: Option<&StripePlan>,
    seats: Option<f64>,
) -> SubscriptionPatch {
    SubscriptionPatch {
        plan: plan.map(StripePlan::persisted_name),
        stripe_subscription_id: Some(Some(subscription.id.clone())),
        status: Some(subscription.status),
        period_start: Some(timestamp(item.current_period_start)),
        period_end: Some(timestamp(item.current_period_end)),
        trial_start: trial_timestamp(subscription.trial_start, subscription.trial_end)
            .map(|(start, _)| Some(start)),
        trial_end: trial_timestamp(subscription.trial_start, subscription.trial_end)
            .map(|(_, end)| Some(end)),
        cancel_at_period_end: Some(subscription.cancel_at_period_end),
        cancel_at: Some(truthy_timestamp(subscription.cancel_at)),
        canceled_at: Some(truthy_timestamp(subscription.canceled_at)),
        ended_at: Some(truthy_timestamp(subscription.ended_at)),
        seats: Some(seats),
        billing_interval: Some(item.price.recurring.as_ref().map(|value| value.interval)),
        stripe_schedule_id: Some(subscription.schedule_id().map(ToOwned::to_owned)),
        ..SubscriptionPatch::default()
    }
}

pub(crate) fn checkout_patch(
    subscription: &StripeSubscription,
    item: &StripeSubscriptionItem,
    plan: &StripePlan,
    checkout_subscription_id: String,
    seats: f64,
) -> SubscriptionPatch {
    let mut patch = lifecycle_patch(subscription, item, Some(plan), Some(seats));
    patch.stripe_subscription_id = Some(Some(checkout_subscription_id));
    patch.stripe_schedule_id = None;
    patch
}

pub(super) fn deletion_patch(subscription: &StripeSubscription) -> SubscriptionPatch {
    SubscriptionPatch {
        status: Some(crate::stripe::SubscriptionStatus::Canceled),
        trial_start: trial_timestamp(subscription.trial_start, subscription.trial_end)
            .map(|(start, _)| Some(start)),
        trial_end: trial_timestamp(subscription.trial_start, subscription.trial_end)
            .map(|(_, end)| Some(end)),
        cancel_at_period_end: Some(subscription.cancel_at_period_end),
        cancel_at: Some(truthy_timestamp(subscription.cancel_at)),
        canceled_at: Some(truthy_timestamp(subscription.canceled_at)),
        ended_at: Some(truthy_timestamp(subscription.ended_at)),
        stripe_schedule_id: Some(None),
        ..SubscriptionPatch::default()
    }
}

fn item_matches_plan(item: &StripeSubscriptionItem, plan: &StripePlan) -> bool {
    plan.price_id.as_deref() == Some(item.price.id.as_str())
        || plan.annual_discount_price_id.as_deref() == Some(item.price.id.as_str())
        || item.price.lookup_key.as_deref().is_some_and(|lookup_key| {
            plan.lookup_key.as_deref() == Some(lookup_key)
                || plan.annual_discount_lookup_key.as_deref() == Some(lookup_key)
        })
}

pub(super) fn trial_timestamp(
    start: Option<i64>,
    end: Option<i64>,
) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    Some((truthy_timestamp(start)?, truthy_timestamp(end)?))
}

fn truthy_timestamp(value: Option<i64>) -> Option<DateTime<Utc>> {
    value.filter(|value| *value != 0).and_then(timestamp)
}

pub(super) fn timestamp(value: i64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(value, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stripe::{
        BillingInterval, CheckoutLineItem, FreeTrial, ProrationBehavior, StripePrice,
        StripeRecurring, StripeSubscriptionItemList, SubscriptionStatus,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn item_resolution_matches_direct_and_lookup_prices_and_preserves_single_item_fallback() {
        let plans = vec![plan("pro", Some("price_direct"), Some("pro-key"))];
        let lookup_item = item("price_other", Some("pro-key"), 3.0);
        let resolved = resolve_plan_item(&plans, std::slice::from_ref(&lookup_item)).unwrap();
        assert_eq!(resolved.plan.map(|plan| plan.name.as_str()), Some("pro"));

        let unmatched = item("unmatched", None, 2.0);
        let resolved = resolve_plan_item(&plans, std::slice::from_ref(&unmatched)).unwrap();
        assert!(resolved.plan.is_none());

        assert!(
            resolve_plan_item(&plans, &[unmatched.clone(), item("other", None, 1.0)]).is_none()
        );
    }

    #[test]
    fn seat_quantity_wins_then_defaults_like_upstream_nullish_coalescing() {
        let mut configured = plan("team", Some("price_base"), None);
        configured.seat_price_id = Some("price_seat".into());
        let subscription = stripe_subscription(vec![
            item("price_base", None, 2.0),
            item("price_seat", None, 0.0),
        ]);
        assert_eq!(
            resolve_quantity(&subscription, &subscription.items.data[0], &configured),
            0.0
        );
        let base_only = stripe_subscription(vec![item("price_base", None, 0.0)]);
        assert_eq!(
            resolve_quantity(&base_only, &base_only.items.data[0], &configured),
            0.0
        );
    }

    #[test]
    fn patches_clear_cancellation_fields_but_only_write_a_complete_truthy_trial() {
        let mut provider = stripe_subscription(vec![item("price_base", None, 2.0)]);
        provider.trial_start = Some(100);
        provider.trial_end = Some(0);
        provider.cancel_at = Some(0);
        let patch = lifecycle_patch(&provider, &provider.items.data[0], None, Some(2.0));
        assert_eq!(patch.trial_start, None);
        assert_eq!(patch.trial_end, None);
        assert_eq!(patch.cancel_at, Some(None));
        assert_eq!(patch.seats, Some(Some(2.0)));
    }

    fn plan(name: &str, price_id: Option<&str>, lookup_key: Option<&str>) -> StripePlan {
        StripePlan {
            name: name.into(),
            price_id: price_id.map(Into::into),
            lookup_key: lookup_key.map(Into::into),
            annual_discount_price_id: None,
            annual_discount_lookup_key: None,
            limits: Some(BTreeMap::from([("requests".into(), json!(100))])),
            group: None,
            seat_price_id: None,
            proration_behavior: ProrationBehavior::default(),
            line_items: Vec::<CheckoutLineItem>::new(),
            free_trial: Some(FreeTrial {
                days: 7,
                callbacks: None,
            }),
        }
    }

    fn item(price_id: &str, lookup_key: Option<&str>, quantity: f64) -> StripeSubscriptionItem {
        StripeSubscriptionItem {
            id: format!("si_{price_id}"),
            price: StripePrice {
                id: price_id.into(),
                active: true,
                lookup_key: lookup_key.map(Into::into),
                recurring: Some(StripeRecurring {
                    interval: BillingInterval::Month,
                    usage_type: None,
                    extra: Default::default(),
                }),
                extra: Default::default(),
            },
            quantity: Some(quantity),
            current_period_start: 100,
            current_period_end: 200,
            extra: Default::default(),
        }
    }

    fn stripe_subscription(items: Vec<StripeSubscriptionItem>) -> StripeSubscription {
        StripeSubscription {
            id: "sub_1".into(),
            customer: json!("cus_1"),
            status: SubscriptionStatus::Active,
            items: StripeSubscriptionItemList { data: items },
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
}
