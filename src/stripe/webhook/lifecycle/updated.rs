use super::{
    LifecycleContext, LifecycleError, customer_to_string, event_object, metadata_string,
    webhook_context,
};
use crate::stripe::webhook::transition::{lifecycle_patch, resolve_plan_item, resolve_quantity};
use crate::stripe::{StripeEvent, StripeSubscription, SubscriptionStatus};
use chrono::Utc;
use uuid::Uuid;

pub(super) async fn handle(
    context: LifecycleContext<'_>,
    event: &StripeEvent,
) -> Result<(), LifecycleError> {
    let Some(options) = context.subscriptions() else {
        return Ok(());
    };
    let stripe_subscription: StripeSubscription = event_object(event)?;
    let plans = options.plans.plans().await?;
    let Some(resolved) = resolve_plan_item(&plans, &stripe_subscription.items.data) else {
        tracing::warn!(
            "Stripe webhook warning: Subscription {} has no items matching a configured plan",
            stripe_subscription.id
        );
        return Ok(());
    };
    let customer_id = customer_to_string(&stripe_subscription.customer).unwrap_or_default();
    let before = match find_target(context, &stripe_subscription, &customer_id).await? {
        Target::Found(subscription) => *subscription,
        Target::MultipleWithoutActive => return Ok(()),
        Target::Missing => {
            return Err(LifecycleError::invalid(
                "subscription update target not found",
            ));
        }
    };
    let seats = resolved
        .plan
        .map(|plan| resolve_quantity(&stripe_subscription, resolved.item, plan))
        .or(resolved.item.quantity);
    let updated = context
        .store
        .update_subscription(
            before.id,
            lifecycle_patch(
                &stripe_subscription,
                resolved.item,
                resolved.plan,
                seats,
                Utc::now(),
            ),
        )
        .await?;
    let Some(updated) = updated else {
        tracing::warn!(
            "Stripe webhook warning: Subscription {} update returned no row (likely deleted concurrently), skipping callbacks",
            before.id
        );
        return Ok(());
    };
    if let Some(callbacks) = &options.callbacks {
        if stripe_subscription.status == SubscriptionStatus::Active
            && stripe_subscription.is_pending_cancel()
            && !before.is_pending_cancel()
        {
            callbacks
                .on_subscription_cancel(
                    event,
                    &stripe_subscription,
                    &updated,
                    stripe_subscription.cancellation_details.as_ref(),
                )
                .await?;
        }
        callbacks
            .on_subscription_update(event, &stripe_subscription, &updated)
            .await?;
    }
    run_trial_transition(resolved.plan, &stripe_subscription, &before, &updated).await
}

async fn find_target(
    context: LifecycleContext<'_>,
    stripe_subscription: &StripeSubscription,
    customer_id: &str,
) -> Result<Target, LifecycleError> {
    let mut local =
        if let Some(id) = metadata_string(&stripe_subscription.metadata, "subscriptionId") {
            match id.parse::<Uuid>() {
                Ok(id) => context.store.find_subscription(id).await?,
                Err(_) => None,
            }
        } else {
            context
                .store
                .find_subscription_by_stripe_id(&stripe_subscription.id)
                .await?
        };
    if let Some(local) = local {
        return Ok(Target::Found(Box::new(local)));
    }
    let rows = context
        .store
        .list_subscriptions_by_customer(customer_id)
        .await?;
    let multiple = rows.len() > 1;
    local = match rows.as_slice() {
        [] => None,
        [only] => Some(only.clone()),
        many => many
            .iter()
            .find(|subscription| subscription.is_active_or_trialing())
            .cloned(),
    };
    if local.is_none() && multiple {
        tracing::warn!(
            "Stripe webhook error: Multiple subscriptions found for customerId: {customer_id} and no active subscription is found"
        );
        return Ok(Target::MultipleWithoutActive);
    }
    Ok(local.map_or(Target::Missing, |subscription| {
        Target::Found(Box::new(subscription))
    }))
}

enum Target {
    Found(Box<crate::stripe::Subscription>),
    MultipleWithoutActive,
    Missing,
}

async fn run_trial_transition(
    plan: Option<&crate::stripe::StripePlan>,
    stripe_subscription: &StripeSubscription,
    before: &crate::stripe::Subscription,
    updated: &crate::stripe::Subscription,
) -> Result<(), LifecycleError> {
    let Some(callbacks) = plan
        .and_then(|plan| plan.free_trial.as_ref())
        .and_then(|trial| trial.callbacks.as_ref())
    else {
        return Ok(());
    };
    if stripe_subscription.status == SubscriptionStatus::Active
        && before.status == SubscriptionStatus::Trialing
    {
        callbacks.on_trial_end(updated, &webhook_context()).await?;
    }
    if stripe_subscription.status == SubscriptionStatus::IncompleteExpired
        && before.status == SubscriptionStatus::Trialing
    {
        callbacks
            .on_trial_expired(updated, &webhook_context())
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stripe::webhook::test_support::{
        FakeStripeClient, event, local_subscription, plan, provider_subscription,
    };
    use crate::stripe::{
        FreeTrial, MemoryStripeStore, StaticPlans, StripeCallbackContext, StripeCallbackError,
        StripeOptions, StripeStore, Subscription, SubscriptionCallbacks, SubscriptionConfiguration,
        SubscriptionOptions, TrialCallbacks,
    };
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct CallbackOrder(Mutex<Vec<&'static str>>);

    #[async_trait]
    impl SubscriptionCallbacks for CallbackOrder {
        async fn on_subscription_cancel(
            &self,
            _event: &StripeEvent,
            _stripe_subscription: &StripeSubscription,
            _subscription: &Subscription,
            _cancellation_details: Option<&serde_json::Value>,
        ) -> Result<(), StripeCallbackError> {
            self.0.lock().unwrap().push("cancel");
            Ok(())
        }

        async fn on_subscription_update(
            &self,
            _event: &StripeEvent,
            _stripe_subscription: &StripeSubscription,
            _subscription: &Subscription,
        ) -> Result<(), StripeCallbackError> {
            self.0.lock().unwrap().push("update");
            Ok(())
        }
    }

    #[async_trait]
    impl TrialCallbacks for CallbackOrder {
        async fn on_trial_end(
            &self,
            _subscription: &Subscription,
            context: &StripeCallbackContext,
        ) -> Result<(), StripeCallbackError> {
            assert_eq!(context.path.as_deref(), Some("/stripe/webhook"));
            self.0.lock().unwrap().push("trial-end");
            Ok(())
        }
    }

    #[tokio::test]
    async fn first_pending_cancel_and_trial_end_callbacks_observe_the_post_update_row_in_order() {
        let recorder = Arc::new(CallbackOrder::default());
        let mut configured_plan = plan();
        configured_plan.free_trial = Some(FreeTrial {
            days: 7,
            callbacks: Some(recorder.clone()),
        });
        let mut provider = provider_subscription(SubscriptionStatus::Active);
        provider.cancel_at_period_end = true;
        let webhook = event(
            "customer.subscription.updated",
            serde_json::to_value(&provider).unwrap(),
        );
        let client = Arc::new(FakeStripeClient::new(webhook.clone()));
        let mut options = StripeOptions::new(client, "whsec_test");
        let mut subscription_options =
            SubscriptionOptions::new(Arc::new(StaticPlans(vec![configured_plan])));
        subscription_options.callbacks = Some(recorder.clone());
        options.subscription = SubscriptionConfiguration::Enabled(subscription_options);
        let store = MemoryStripeStore::new();
        let mut before = local_subscription("owner");
        before.status = SubscriptionStatus::Trialing;
        store.create_subscription(before.clone()).await.unwrap();

        handle(
            LifecycleContext {
                options: &options,
                store: &store,
            },
            &webhook,
        )
        .await
        .unwrap();

        assert_eq!(
            *recorder.0.lock().unwrap(),
            vec!["cancel", "update", "trial-end"]
        );
        let updated = store.find_subscription(before.id).await.unwrap().unwrap();
        assert_eq!(updated.status, SubscriptionStatus::Active);
        assert!(updated.cancel_at_period_end);
    }
}
