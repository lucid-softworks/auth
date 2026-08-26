use super::{LifecycleContext, LifecycleError, event_object};
use crate::stripe::webhook::transition::deletion_patch;
use crate::stripe::{StripeEvent, StripeSubscription};

pub(super) async fn handle(
    context: LifecycleContext<'_>,
    event: &StripeEvent,
) -> Result<(), LifecycleError> {
    let Some(options) = context.subscriptions() else {
        return Ok(());
    };
    let stripe_subscription: StripeSubscription = event_object(event)?;
    let Some(local) = context
        .store
        .find_subscription_by_stripe_id(&stripe_subscription.id)
        .await?
    else {
        tracing::warn!(
            "Stripe webhook error: Subscription not found for subscriptionId: {}",
            stripe_subscription.id
        );
        return Ok(());
    };
    let updated = context
        .store
        .update_subscription(local.id, deletion_patch(&stripe_subscription))
        .await?;
    let Some(updated) = updated else {
        tracing::warn!(
            "Stripe webhook warning: Subscription {} update returned no row (likely deleted concurrently), skipping callbacks",
            local.id
        );
        return Ok(());
    };
    if let Some(callbacks) = &options.callbacks {
        callbacks
            .on_subscription_deleted(event, &stripe_subscription, &updated)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stripe::webhook::test_support::{
        FakeStripeClient, enabled_options, event, local_subscription, provider_subscription,
    };
    use crate::stripe::{
        MemoryStripeStore, StripeCallbackError, StripeStore, Subscription, SubscriptionCallbacks,
        SubscriptionConfiguration, SubscriptionStatus,
    };
    use async_trait::async_trait;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct DeletedRecorder(AtomicUsize);

    #[async_trait]
    impl SubscriptionCallbacks for DeletedRecorder {
        async fn on_subscription_deleted(
            &self,
            _event: &StripeEvent,
            _stripe_subscription: &StripeSubscription,
            subscription: &Subscription,
        ) -> Result<(), StripeCallbackError> {
            assert_eq!(subscription.status, SubscriptionStatus::Canceled);
            assert!(subscription.stripe_schedule_id.is_none());
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn deletion_cancels_the_target_clears_its_schedule_and_calls_back_once() {
        let provider = provider_subscription(SubscriptionStatus::Canceled);
        let webhook = event(
            "customer.subscription.deleted",
            serde_json::to_value(&provider).unwrap(),
        );
        let client = Arc::new(FakeStripeClient::new(webhook.clone()));
        let recorder = Arc::new(DeletedRecorder::default());
        let mut options = enabled_options(client);
        let SubscriptionConfiguration::Enabled(subscription) = &mut options.subscription else {
            unreachable!();
        };
        subscription.callbacks = Some(recorder.clone());
        let store = MemoryStripeStore::new();
        let mut local = local_subscription("owner");
        local.stripe_schedule_id = Some("sub_sched".into());
        store.create_subscription(local.clone()).await.unwrap();

        handle(
            LifecycleContext {
                options: &options,
                store: &store,
            },
            &webhook,
        )
        .await
        .unwrap();

        let updated = store.find_subscription(local.id).await.unwrap().unwrap();
        assert_eq!(updated.status, SubscriptionStatus::Canceled);
        assert!(updated.stripe_schedule_id.is_none());
        assert_eq!(recorder.0.load(Ordering::SeqCst), 1);
    }
}
