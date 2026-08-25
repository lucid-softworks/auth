use super::{LifecycleContext, LifecycleError, event_object, metadata_string, webhook_context};
use crate::stripe::webhook::transition::{
    checkout_patch, resolve_plan_item, resolve_quantity, trial_timestamp,
};
use crate::stripe::{StripeCheckoutSession, StripeEvent, SubscriptionOptions};
use chrono::Utc;
use uuid::Uuid;

pub(super) async fn handle(
    context: LifecycleContext<'_>,
    event: &StripeEvent,
) -> Result<(), LifecycleError> {
    let Some(options) = context.subscriptions() else {
        return Ok(());
    };
    let checkout: StripeCheckoutSession = event_object(event)?;
    if checkout.mode.as_deref() == Some("setup") {
        return Ok(());
    }
    complete(context, options, event, checkout).await
}

async fn complete(
    context: LifecycleContext<'_>,
    options: &SubscriptionOptions,
    event: &StripeEvent,
    checkout: StripeCheckoutSession,
) -> Result<(), LifecycleError> {
    let stripe_subscription_id = checkout
        .subscription_id()
        .ok_or_else(|| LifecycleError::invalid("checkout session has no subscription"))?;
    let stripe_subscription = context
        .options
        .client
        .retrieve_subscription(stripe_subscription_id)
        .await?;
    let plans = options.plans.plans().await?;
    let Some(resolved) = resolve_plan_item(&plans, &stripe_subscription.items.data) else {
        tracing::warn!(
            "Stripe webhook warning: Subscription {} has no items matching a configured plan",
            stripe_subscription.id
        );
        return Ok(());
    };
    let Some(plan) = resolved.plan else {
        return Ok(());
    };
    let reference_id = checkout
        .client_reference_id
        .as_deref()
        .or_else(|| metadata_string(&checkout.metadata, "referenceId"));
    let local_id = metadata_string(&checkout.metadata, "subscriptionId")
        .and_then(|value| value.parse::<Uuid>().ok());
    let (Some(_reference_id), Some(local_id)) = (reference_id, local_id) else {
        return Ok(());
    };
    let seats = resolve_quantity(&stripe_subscription, resolved.item, plan);
    let patch = checkout_patch(
        &stripe_subscription,
        resolved.item,
        plan,
        stripe_subscription_id.to_owned(),
        seats,
        Utc::now(),
    );
    let mut local = context.store.update_subscription(local_id, patch).await?;

    if trial_timestamp(
        stripe_subscription.trial_start,
        stripe_subscription.trial_end,
    )
    .is_some()
        && let (Some(callbacks), Some(subscription)) = (
            plan.free_trial
                .as_ref()
                .and_then(|trial| trial.callbacks.as_ref()),
            local.as_ref(),
        )
    {
        callbacks.on_trial_start(subscription).await?;
    }
    if local.is_none() {
        local = context.store.find_subscription(local_id).await?;
    }
    if let (Some(callbacks), Some(subscription)) = (options.callbacks.as_ref(), local.as_ref()) {
        callbacks
            .on_subscription_complete(
                event,
                &stripe_subscription,
                subscription,
                plan,
                &webhook_context(),
            )
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
        StripeMetadata, StripeOptions, StripeStore, StripeSubscription, Subscription,
        SubscriptionCallbacks, SubscriptionConfiguration, SubscriptionOptions, SubscriptionStatus,
        TrialCallbacks,
    };
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct CompletionOrder(Mutex<Vec<&'static str>>);

    #[async_trait]
    impl TrialCallbacks for CompletionOrder {
        async fn on_trial_start(
            &self,
            subscription: &Subscription,
        ) -> Result<(), StripeCallbackError> {
            assert_eq!(subscription.status, SubscriptionStatus::Trialing);
            self.0.lock().unwrap().push("trial-start");
            Ok(())
        }
    }

    #[async_trait]
    impl SubscriptionCallbacks for CompletionOrder {
        async fn on_subscription_complete(
            &self,
            _event: &StripeEvent,
            _stripe_subscription: &StripeSubscription,
            subscription: &Subscription,
            _plan: &crate::stripe::StripePlan,
            context: &StripeCallbackContext,
        ) -> Result<(), StripeCallbackError> {
            assert_eq!(context.method.as_deref(), Some("POST"));
            assert_eq!(subscription.status, SubscriptionStatus::Trialing);
            self.0.lock().unwrap().push("complete");
            Ok(())
        }
    }

    #[tokio::test]
    async fn checkout_updates_the_precreated_row_then_runs_trial_start_and_complete() {
        let store = MemoryStripeStore::new();
        let local = local_subscription("owner");
        store.create_subscription(local.clone()).await.unwrap();
        let mut provider = provider_subscription(SubscriptionStatus::Trialing);
        provider.trial_start = Some(100);
        provider.trial_end = Some(200);
        let checkout = StripeCheckoutSession {
            id: "cs_1".into(),
            url: None,
            mode: Some("subscription".into()),
            subscription: Some(json!("sub_1")),
            customer: Some(json!("cus_1")),
            payment_status: Some("paid".into()),
            client_reference_id: Some("owner".into()),
            metadata: StripeMetadata::from([
                ("subscriptionId".into(), json!(local.id.to_string())),
                ("referenceId".into(), json!("owner")),
            ]),
            extra: Default::default(),
        };
        let webhook = event(
            "checkout.session.completed",
            serde_json::to_value(checkout).unwrap(),
        );
        let client = Arc::new(FakeStripeClient::with_subscription(
            webhook.clone(),
            provider,
        ));
        let recorder = Arc::new(CompletionOrder::default());
        let mut configured_plan = plan();
        configured_plan.free_trial = Some(FreeTrial {
            days: 7,
            callbacks: Some(recorder.clone()),
        });
        let mut subscription_options =
            SubscriptionOptions::new(Arc::new(StaticPlans(vec![configured_plan])));
        subscription_options.callbacks = Some(recorder.clone());
        let mut options = StripeOptions::new(client, "whsec_test");
        options.subscription = SubscriptionConfiguration::Enabled(subscription_options);

        handle(
            LifecycleContext {
                options: &options,
                store: &store,
            },
            &webhook,
        )
        .await
        .unwrap();

        assert_eq!(*recorder.0.lock().unwrap(), vec!["trial-start", "complete"]);
        let updated = store.find_subscription(local.id).await.unwrap().unwrap();
        assert_eq!(updated.status, SubscriptionStatus::Trialing);
        assert_eq!(updated.stripe_subscription_id.as_deref(), Some("sub_1"));
    }
}
