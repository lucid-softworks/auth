use super::{LifecycleError, log_failure, mapping};
use crate::chargebee::{
    ChargebeeOptions, ChargebeeProviderCustomer, ChargebeeProviderSubscription, ChargebeeStore,
    ChargebeeSubscription,
};
use chrono::{DateTime, Utc};

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
    if customer.id.is_empty() {
        tracing::warn!(
            "Chargebee webhook warning: subscription event received without customer ID"
        );
        return Ok(());
    }
    if let Some(existing) = store
        .find_subscription_by_chargebee_id(&provider.id)
        .await?
    {
        tracing::info!(
            subscription_id = %existing.id,
            "Chargebee webhook: Subscription already exists in database, skipping creation"
        );
        return Ok(());
    }

    let Some(reference_id) = find_reference(options, store, &customer.id).await? else {
        tracing::warn!(
            customer_id = %customer.id,
            "Chargebee webhook warning: No user or organization found with chargebeeCustomerId"
        );
        return Ok(());
    };
    let Some(primary) = provider.subscription_items.first() else {
        tracing::warn!(
            subscription_id = %provider.id,
            "Chargebee webhook warning: Subscription has no items"
        );
        return Ok(());
    };
    let plan = mapping::plan(options, &primary.item_price_id).await?;
    if plan.is_none() {
        tracing::warn!(
            item_price_id = %primary.item_price_id,
            "Chargebee webhook warning: No matching plan; subscription will still be tracked"
        );
    }

    let (local, has_trial) = create_local(store, provider, customer, reference_id).await?;

    if let Some(callbacks) = options
        .subscription
        .as_ref()
        .and_then(|subscription| subscription.callbacks.as_ref())
    {
        callbacks
            .on_subscription_created(&local, provider, plan.as_ref())
            .await?;
        if has_trial {
            callbacks.on_trial_start(&local, Some(provider)).await?;
        }
    }
    tracing::info!(
        chargebee_subscription_id = %provider.id,
        reference_id = %local.reference_id,
        "Chargebee webhook: Created subscription"
    );
    Ok(())
}

async fn create_local(
    store: &dyn ChargebeeStore,
    provider: &ChargebeeProviderSubscription,
    customer: &ChargebeeProviderCustomer,
    reference_id: String,
) -> Result<(ChargebeeSubscription, bool), LifecycleError> {
    let now = Utc::now();
    let trial =
        mapping::timestamp(provider.trial_start)?.zip(mapping::timestamp(provider.trial_end)?);
    let has_trial = trial.is_some();
    let mut local = ChargebeeSubscription::future(reference_id);
    local.chargebee_customer_id = Some(customer.id.clone());
    local.chargebee_subscription_id = Some(provider.id.clone());
    local.status = mapping::status(&provider.status);
    local.period_start = mapping::timestamp(provider.current_term_start)?.or(Some(now));
    local.period_end = mapping::timestamp(provider.current_term_end)?;
    local.seats = provider
        .subscription_items
        .first()
        .map(|item| mapping::quantity(item.quantity));
    if let Some((start, end)) = trial {
        set_trial(&mut local, start, end);
    }
    let local = store.create_subscription(local).await?;
    for provider_item in &provider.subscription_items {
        store
            .create_subscription_item(mapping::item(local.id, provider_item))
            .await?;
    }
    Ok((local, has_trial))
}

fn set_trial(subscription: &mut ChargebeeSubscription, start: DateTime<Utc>, end: DateTime<Utc>) {
    subscription.trial_start = Some(start);
    subscription.trial_end = Some(end);
}

async fn find_reference(
    options: &ChargebeeOptions,
    store: &dyn ChargebeeStore,
    customer_id: &str,
) -> Result<Option<String>, LifecycleError> {
    if options.organization_enabled()
        && let Some(organization_id) = store.organization_id_by_customer(customer_id).await?
    {
        return Ok(Some(organization_id.to_string()));
    }
    Ok(store
        .user_id_by_customer(customer_id)
        .await?
        .map(|user_id| user_id.to_string()))
}
