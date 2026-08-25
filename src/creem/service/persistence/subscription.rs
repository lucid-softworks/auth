use super::value::{
    optional_string, parsed_truthy_date, required_object_like_member, truthy, truthy_string_member,
};
use crate::creem::{
    CreemPersistenceError, CreemStore, CreemStoredUser, CreemSubscription, CreemSubscriptionPatch,
};
use serde_json::{Map, Value};

pub(super) async fn persist(
    store: &dyn CreemStore,
    event_type: &str,
    data: &Map<String, Value>,
) -> Result<(), CreemPersistenceError> {
    let Some(reference_id) = nested_reference_id(data)? else {
        return Ok(());
    };
    let customer_id = optional_string(
        required_object_like_member(data, "customer", "id")?,
        "customer.id",
    )?;
    let product_id = optional_string(
        required_object_like_member(data, "product", "id")?,
        "product.id",
    )?;
    let provider_id = optional_string(data.get("id"), "subscription.id")?;

    let mut subscription = match provider_id.as_deref() {
        Some(id) => store
            .find_subscription_by_creem_id(id)
            .await
            .map_err(store_error)?,
        None => None,
    };
    if subscription.is_none()
        && let Some(customer_id) = customer_id.as_deref().filter(|value| !value.is_empty())
    {
        let candidates = store
            .list_subscriptions_by_customer(customer_id)
            .await
            .map_err(store_error)?;
        subscription = select_customer_fallback(candidates, product_id.as_deref());
    }
    let Some(subscription) = subscription else {
        return Ok(());
    };

    let status = event_status(event_type, data)?;
    let period_start = parsed_truthy_date(
        data.get("current_period_start_date"),
        "subscription.current_period_start_date",
    )?
    .or(subscription.period_start);
    let period_end = parsed_truthy_date(
        data.get("current_period_end_date"),
        "subscription.current_period_end_date",
    )?
    .or(subscription.period_end);
    store
        .update_subscription(
            subscription.id,
            CreemSubscriptionPatch {
                status,
                creem_customer_id: customer_id.map(Some),
                creem_subscription_id: provider_id.map(Some),
                period_start: Some(period_start),
                period_end: Some(period_end),
                ..CreemSubscriptionPatch::default()
            },
        )
        .await
        .map_err(store_error)?;
    let _ = reference_id;
    Ok(())
}

pub(super) async fn mark_trial(
    store: &dyn CreemStore,
    data: &Map<String, Value>,
) -> Result<(), CreemPersistenceError> {
    let Some(reference_id) = nested_reference_id(data)? else {
        return Ok(());
    };
    let user = store.find_user(&reference_id).await.map_err(store_error)?;
    if user.as_ref().is_some_and(user_needs_trial_mark) {
        store
            .set_user_had_trial(&reference_id, true)
            .await
            .map_err(store_error)?;
    }
    Ok(())
}

fn nested_reference_id(data: &Map<String, Value>) -> Result<Option<String>, CreemPersistenceError> {
    let Some(metadata) = data.get("metadata").and_then(Value::as_object) else {
        return Ok(None);
    };
    truthy_string_member(metadata, "referenceId").map(|value| value.map(str::to_owned))
}

fn select_customer_fallback(
    candidates: Vec<CreemSubscription>,
    product_id: Option<&str>,
) -> Option<CreemSubscription> {
    candidates
        .iter()
        .find(|subscription| Some(subscription.product_id.as_str()) == product_id)
        .cloned()
        .or_else(|| candidates.into_iter().next())
}

fn event_status(
    event_type: &str,
    data: &Map<String, Value>,
) -> Result<Option<String>, CreemPersistenceError> {
    let mapped = match event_type {
        "subscription.active" => Some("active"),
        "subscription.trialing" => Some("trialing"),
        "subscription.canceled" => Some("canceled"),
        "subscription.expired" => Some("expired"),
        "subscription.unpaid" => Some("unpaid"),
        "subscription.past_due" => Some("past_due"),
        "subscription.paused" => Some("paused"),
        "subscription.paid" | "subscription.update" => None,
        _ => return Ok(None),
    };
    mapped.map(|status| Some(status.to_owned())).map_or_else(
        || optional_string(data.get("status"), "subscription.status"),
        Ok,
    )
}

fn user_needs_trial_mark(user: &CreemStoredUser) -> bool {
    !user.had_trial.as_ref().is_some_and(truthy)
}

fn store_error(error: crate::creem::CreemStoreError) -> CreemPersistenceError {
    CreemPersistenceError::new(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn customer_fallback_prefers_matching_product_then_store_order() {
        let first = CreemSubscription::new("first", "owner");
        let matching = CreemSubscription::new("matching", "owner");
        assert_eq!(
            select_customer_fallback(vec![first.clone(), matching.clone()], Some("matching"))
                .unwrap()
                .id,
            matching.id
        );
        assert_eq!(
            select_customer_fallback(vec![first.clone(), matching], Some("absent"))
                .unwrap()
                .id,
            first.id
        );
    }

    #[test]
    fn event_status_uses_payload_only_for_paid_and_update() {
        let data = Map::from_iter([("status".into(), Value::String("custom".into()))]);
        assert_eq!(
            event_status("subscription.active", &data).unwrap(),
            Some("active".into())
        );
        assert_eq!(
            event_status("subscription.paid", &data).unwrap(),
            Some("custom".into())
        );
        assert_eq!(
            event_status("subscription.update", &data).unwrap(),
            Some("custom".into())
        );
    }
}
