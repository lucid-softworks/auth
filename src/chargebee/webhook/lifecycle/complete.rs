use super::{LifecycleError, log_failure, mapping};
use crate::chargebee::{
    ChargebeeOptions, ChargebeeProviderCustomer, ChargebeeProviderSubscription, ChargebeeStore,
    ChargebeeSubscription, ChargebeeSubscriptionPatch,
};
use chrono::Utc;
use uuid::Uuid;

pub(in crate::chargebee::webhook) async fn handle(
    options: &ChargebeeOptions,
    store: &dyn ChargebeeStore,
    subscription: ChargebeeProviderSubscription,
    customer: ChargebeeProviderCustomer,
) {
    if let Err(error) = handle_inner(options, store, &subscription, &customer).await {
        log_failure(&error);
    }
}

async fn handle_inner(
    options: &ChargebeeOptions,
    store: &dyn ChargebeeStore,
    provider: &ChargebeeProviderSubscription,
    customer: &ChargebeeProviderCustomer,
) -> Result<(), LifecycleError> {
    if !options.subscriptions_enabled() {
        return Ok(());
    }
    let Some(primary) = provider.subscription_items.first() else {
        tracing::warn!(
            subscription_id = %provider.id,
            "Chargebee webhook warning: Subscription has no items"
        );
        return Ok(());
    };
    let Some(local) = find_pending(store, provider, customer).await? else {
        tracing::warn!(
            subscription_id = %provider.id,
            "Chargebee webhook warning: Subscription not found"
        );
        return Ok(());
    };

    let plan = mapping::plan(options, &primary.item_price_id).await?;
    let now = Utc::now();
    let trial_start = mapping::timestamp(provider.trial_start)?;
    let trial_end = mapping::timestamp(provider.trial_end)?;
    let trial = trial_start.zip(trial_end);
    let mut patch = ChargebeeSubscriptionPatch {
        chargebee_subscription_id: Some(Some(provider.id.clone())),
        chargebee_customer_id: Some(Some(customer.id.clone())),
        status: Some(mapping::status(&provider.status)),
        updated_at: Some(now),
        period_start: Some(Some(
            mapping::timestamp(provider.current_term_start)?.unwrap_or(now),
        )),
        period_end: Some(mapping::timestamp(provider.current_term_end)?),
        seats: Some(Some(mapping::quantity(primary.quantity))),
        ..ChargebeeSubscriptionPatch::default()
    };
    if let Some((start, end)) = trial {
        patch.trial_start = Some(Some(start));
        patch.trial_end = Some(Some(end));
    }
    let update_result = store.update_subscription(local.id, patch).await?;
    let refetched = if update_result.is_none() {
        store.find_subscription(local.id).await?
    } else {
        None
    };
    let Some(updated) = resolved_update(update_result, refetched) else {
        tracing::warn!(
            subscription_id = %local.id,
            "Chargebee webhook warning: Updated subscription no longer exists"
        );
        return Ok(());
    };

    if let Some(callbacks) = options
        .subscription
        .as_ref()
        .and_then(|subscription| subscription.callbacks.as_ref())
    {
        if trial.is_some() {
            callbacks.on_trial_start(&updated, Some(provider)).await?;
        }
        callbacks
            .on_subscription_complete(&updated, provider, plan.as_ref())
            .await?;
    }
    tracing::info!(
        chargebee_subscription_id = %provider.id,
        "Chargebee webhook: Subscription completed successfully"
    );
    Ok(())
}

fn resolved_update(
    updated: Option<ChargebeeSubscription>,
    refetched: Option<ChargebeeSubscription>,
) -> Option<ChargebeeSubscription> {
    updated.or(refetched)
}

async fn find_pending(
    store: &dyn ChargebeeStore,
    provider: &ChargebeeProviderSubscription,
    customer: &ChargebeeProviderCustomer,
) -> Result<Option<ChargebeeSubscription>, LifecycleError> {
    if let Some(local) = store
        .find_subscription_by_chargebee_id(&provider.id)
        .await?
    {
        return Ok(Some(local));
    }
    for id in [
        mapping::metadata_string(provider.metadata.as_ref(), "subscriptionId"),
        mapping::metadata_string(customer.metadata.as_ref(), "pendingSubscriptionId"),
    ]
    .into_iter()
    .flatten()
    {
        if let Ok(id) = Uuid::parse_str(id)
            && let Some(local) = store.find_subscription(id).await?
        {
            return Ok(Some(local));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_update_and_refetch_never_fall_back_to_stale_local_state() {
        let stale = ChargebeeSubscription::future("user", Utc::now());

        assert!(resolved_update(None, None).is_none());
        assert_eq!(resolved_update(None, Some(stale.clone())), Some(stale));
    }
}
