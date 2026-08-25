use super::{LifecycleError, log_failure, mapping};
use crate::chargebee::{
    ChargebeeOptions, ChargebeeProviderSubscription, ChargebeeStore, ChargebeeSubscriptionPatch,
    ChargebeeSubscriptionStatus,
};
use chrono::Utc;

pub(in crate::chargebee::webhook) async fn handle(
    options: &ChargebeeOptions,
    store: &dyn ChargebeeStore,
    subscription: ChargebeeProviderSubscription,
) {
    if let Err(error) = handle_inner(options, store, &subscription).await {
        log_failure(&error);
    }
}

async fn handle_inner(
    options: &ChargebeeOptions,
    store: &dyn ChargebeeStore,
    provider: &ChargebeeProviderSubscription,
) -> Result<(), LifecycleError> {
    if !options.subscriptions_enabled() {
        return Ok(());
    }
    let Some(local) = store
        .find_subscription_by_chargebee_id(&provider.id)
        .await?
    else {
        tracing::warn!(
            subscription_id = %provider.id,
            "Chargebee webhook error: Subscription not found"
        );
        return Ok(());
    };

    let provider_canceled_at = mapping::timestamp(provider.cancelled_at)?;
    let stored_canceled_at = provider_canceled_at.unwrap_or_else(Utc::now);
    store
        .update_subscription(
            local.id,
            ChargebeeSubscriptionPatch {
                status: Some(ChargebeeSubscriptionStatus::Cancelled),
                updated_at: Some(Utc::now()),
                canceled_at: Some(Some(stored_canceled_at)),
                ..ChargebeeSubscriptionPatch::default()
            },
        )
        .await?;

    if let Some(callbacks) = options
        .subscription
        .as_ref()
        .and_then(|subscription| subscription.callbacks.as_ref())
    {
        let mut callback_subscription = local;
        callback_subscription.status = ChargebeeSubscriptionStatus::Cancelled;
        callback_subscription.canceled_at = Some(provider_canceled_at.unwrap_or_else(Utc::now));
        callbacks
            .on_subscription_deleted(&callback_subscription, Some(provider))
            .await?;
    }
    Ok(())
}
