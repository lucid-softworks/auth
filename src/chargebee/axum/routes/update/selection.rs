use crate::chargebee::{
    ChargebeeProviderSubscription, ChargebeeSubscription, ChargebeeSubscriptionStatus,
};
use chrono::Utc;

pub(super) fn provider_is_active(subscription: &ChargebeeProviderSubscription) -> bool {
    matches!(
        subscription.status.as_str(),
        "active" | "in_trial" | "non_renewing"
    )
}

pub(super) fn already_subscribed(
    requested: &[String],
    quantity: f64,
    local: Option<&ChargebeeSubscription>,
    provider: &ChargebeeProviderSubscription,
) -> bool {
    let current = provider
        .subscription_items
        .iter()
        .map(|item| item.item_price_id.as_str())
        .collect::<Vec<_>>();
    local.is_some_and(|local| {
        local.status == ChargebeeSubscriptionStatus::Active
            && requested.len() == current.len()
            && requested.iter().all(|id| current.contains(&id.as_str()))
            && local.seats == Some(quantity)
            && local
                .period_end
                .is_none_or(|period_end| period_end > Utc::now())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn provider(ids: &[&str]) -> ChargebeeProviderSubscription {
        ChargebeeProviderSubscription {
            id: "provider".into(),
            customer_id: "customer".into(),
            status: "active".into(),
            current_term_start: None,
            current_term_end: None,
            trial_start: None,
            trial_end: None,
            cancelled_at: None,
            subscription_items: ids
                .iter()
                .map(|id| crate::chargebee::ChargebeeProviderSubscriptionItem {
                    item_price_id: (*id).into(),
                    item_type: None,
                    quantity: None,
                    unit_price: None,
                    amount: None,
                    extra: BTreeMap::new(),
                })
                .collect(),
            metadata: None,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn unchanged_check_is_order_insensitive_but_not_multiset_equality() {
        let mut local = ChargebeeSubscription::future("user", Utc::now());
        local.status = ChargebeeSubscriptionStatus::Active;
        local.seats = Some(1.0);
        assert!(already_subscribed(
            &["two".into(), "one".into()],
            1.0,
            Some(&local),
            &provider(&["one", "two"]),
        ));
        assert!(already_subscribed(
            &["one".into(), "one".into()],
            1.0,
            Some(&local),
            &provider(&["one", "two"]),
        ));
    }
}
