use super::{LifecycleError, log_failure, mapping};
use crate::chargebee::{
    ChargebeeOptions, ChargebeeProviderCustomer, ChargebeeProviderSubscription, ChargebeeStore,
    ChargebeeSubscription, ChargebeeSubscriptionPatch, ChargebeeSubscriptionStatus,
};

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
    let Some(local) = find_local(store, provider, &customer.id).await? else {
        tracing::warn!(
            subscription_id = %provider.id,
            "Chargebee webhook warning: Subscription not found"
        );
        return Ok(());
    };

    let was_trialing = local.status == ChargebeeSubscriptionStatus::InTrial;
    let next_status = mapping::status(&provider.status);
    let updated = store
        .update_subscription(
            local.id,
            ChargebeeSubscriptionPatch {
                chargebee_subscription_id: Some(Some(provider.id.clone())),
                status: Some(next_status.clone()),
                period_start: mapping::timestamp(provider.current_term_start)?.map(Some),
                period_end: mapping::timestamp(provider.current_term_end)?.map(Some),
                canceled_at: Some(mapping::timestamp(provider.cancelled_at)?),
                trial_start: Some(mapping::timestamp(provider.trial_start)?),
                trial_end: Some(mapping::timestamp(provider.trial_end)?),
                seats: Some(Some(mapping::quantity(primary.quantity))),
                ..ChargebeeSubscriptionPatch::default()
            },
        )
        .await?
        .unwrap_or_else(|| local.clone());

    store.delete_subscription_items(local.id).await?;
    for provider_item in &provider.subscription_items {
        store
            .create_subscription_item(mapping::item(local.id, provider_item))
            .await?;
    }

    if let Some(callbacks) = options
        .subscription
        .as_ref()
        .and_then(|subscription| subscription.callbacks.as_ref())
    {
        let newly_cancelled = provider.status == "active"
            && provider
                .cancelled_at
                .is_some_and(|timestamp| timestamp != 0)
            && local.canceled_at.is_none();
        if newly_cancelled {
            callbacks.on_subscription_cancel(&updated, provider).await?;
        }
        callbacks
            .on_subscription_update(&updated, Some(provider))
            .await?;
        if was_trialing && next_status == ChargebeeSubscriptionStatus::Active {
            callbacks.on_trial_end(&updated, Some(provider)).await?;
        }
    }
    Ok(())
}

async fn find_local(
    store: &dyn ChargebeeStore,
    provider: &ChargebeeProviderSubscription,
    customer_id: &str,
) -> Result<Option<ChargebeeSubscription>, LifecycleError> {
    if let Some(local) = store
        .find_subscription_by_chargebee_id(&provider.id)
        .await?
    {
        return Ok(Some(local));
    }
    let locals = store.list_subscriptions_by_customer(customer_id).await?;
    if locals.len() > 1 {
        let active = locals.into_iter().find(ChargebeeSubscription::is_active);
        if active.is_none() {
            tracing::warn!(
                customer_id,
                "Chargebee webhook error: Multiple subscriptions found and no active subscription is found"
            );
        }
        Ok(active)
    } else {
        Ok(locals.into_iter().next())
    }
}
