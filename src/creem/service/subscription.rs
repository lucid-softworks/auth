#[cfg(feature = "axum")]
use crate::creem::CreemStore;
use crate::creem::{CreemStoreError, CreemSubscription};

const CANCELABLE_STATUSES: &[&str] = &["active", "trialing", "unpaid", "past_due"];

#[derive(Debug, thiserror::Error)]
pub(crate) enum CreemSubscriptionSelectionError {
    #[error("Subscription ID is required when database persistence is disabled")]
    #[cfg(feature = "axum")]
    PersistenceDisabledIdRequired,
    #[error("No active subscription found for this user")]
    NoActiveSubscription,
    #[error("No subscription found for this user")]
    NoSubscription,
    #[error(transparent)]
    Store(#[from] CreemStoreError),
}

#[cfg(feature = "axum")]
pub(crate) async fn cancel_subscription_id(
    store: &dyn CreemStore,
    reference_id: &str,
    supplied_id: Option<&str>,
    persist_subscriptions: bool,
) -> Result<String, CreemSubscriptionSelectionError> {
    if !persist_subscriptions {
        return truthy(supplied_id)
            .map(str::to_owned)
            .ok_or(CreemSubscriptionSelectionError::PersistenceDisabledIdRequired);
    }
    let subscriptions = store.list_subscriptions_by_reference(reference_id).await?;
    select_cancel_id(&subscriptions, supplied_id)
}

#[cfg(feature = "axum")]
pub(crate) async fn retrieve_subscription_id(
    store: &dyn CreemStore,
    reference_id: &str,
    supplied_id: Option<&str>,
    persist_subscriptions: bool,
) -> Result<String, CreemSubscriptionSelectionError> {
    if !persist_subscriptions {
        return truthy(supplied_id)
            .map(str::to_owned)
            .ok_or(CreemSubscriptionSelectionError::PersistenceDisabledIdRequired);
    }
    let subscriptions = store.list_subscriptions_by_reference(reference_id).await?;
    select_retrieve_id(&subscriptions, supplied_id)
}

fn select_cancel_id(
    subscriptions: &[CreemSubscription],
    supplied_id: Option<&str>,
) -> Result<String, CreemSubscriptionSelectionError> {
    let supplied_id = truthy(supplied_id);
    if subscriptions.is_empty() {
        return supplied_id
            .map(str::to_owned)
            .ok_or(CreemSubscriptionSelectionError::NoSubscription);
    }
    let stored_id = subscriptions
        .iter()
        .find(|subscription| CANCELABLE_STATUSES.contains(&subscription.status.as_str()))
        .and_then(|subscription| truthy(subscription.creem_subscription_id.as_deref()));
    stored_id
        .or(supplied_id)
        .map(str::to_owned)
        .ok_or(CreemSubscriptionSelectionError::NoActiveSubscription)
}

fn select_retrieve_id(
    subscriptions: &[CreemSubscription],
    supplied_id: Option<&str>,
) -> Result<String, CreemSubscriptionSelectionError> {
    subscriptions
        .first()
        .and_then(|subscription| truthy(subscription.creem_subscription_id.as_deref()))
        .or_else(|| truthy(supplied_id))
        .map(str::to_owned)
        .ok_or(CreemSubscriptionSelectionError::NoSubscription)
}

fn truthy(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_inspects_only_the_first_exactly_eligible_row() {
        let first = subscription("active", None);
        let second = subscription("trialing", Some("later"));
        assert!(matches!(
            select_cancel_id(&[first.clone(), second], None),
            Err(CreemSubscriptionSelectionError::NoActiveSubscription)
        ));
        assert_eq!(
            select_cancel_id(&[first], Some("caller")).unwrap(),
            "caller"
        );
        assert!(matches!(
            select_cancel_id(&[subscription("Active", Some("wrong-case"))], None),
            Err(CreemSubscriptionSelectionError::NoActiveSubscription)
        ));
    }

    #[test]
    fn cancel_and_retrieve_preserve_store_order_and_stored_precedence() {
        let first = subscription("expired", Some("first"));
        let second = subscription("active", Some("active"));
        assert_eq!(
            select_cancel_id(&[first.clone(), second.clone()], Some("caller")).unwrap(),
            "active"
        );
        assert_eq!(
            select_retrieve_id(&[first, second], Some("caller")).unwrap(),
            "first"
        );
    }

    #[test]
    fn empty_ids_are_javascript_falsey() {
        assert!(matches!(
            select_cancel_id(&[], Some("")),
            Err(CreemSubscriptionSelectionError::NoSubscription)
        ));
        assert_eq!(
            select_retrieve_id(&[subscription("active", Some(""))], Some("caller")).unwrap(),
            "caller"
        );
    }

    fn subscription(status: &str, provider_id: Option<&str>) -> CreemSubscription {
        let mut subscription = CreemSubscription::new("product", "owner");
        subscription.status = status.into();
        subscription.creem_subscription_id = provider_id.map(str::to_owned);
        subscription
    }
}
