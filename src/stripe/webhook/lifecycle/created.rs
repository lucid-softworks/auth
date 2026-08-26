use super::{LifecycleContext, LifecycleError, customer_to_string, event_object, metadata_string};
use crate::stripe::webhook::transition::{
    resolve_plan_item, resolve_quantity, timestamp, trial_timestamp,
};
use crate::stripe::{StripeEvent, StripePlan, StripeSubscription, Subscription};
use uuid::Uuid;

pub(super) async fn handle(
    context: LifecycleContext<'_>,
    event: &StripeEvent,
) -> Result<(), LifecycleError> {
    let Some(options) = context.subscriptions() else {
        return Ok(());
    };
    let stripe_subscription: StripeSubscription = event_object(event)?;
    let Some(customer_id) = customer_to_string(&stripe_subscription.customer) else {
        tracing::warn!(
            "Stripe webhook warning: customer.subscription.created event received without customer ID"
        );
        return Ok(());
    };
    if let Some(existing) = find_duplicate(context, &stripe_subscription).await? {
        tracing::info!(
            "Stripe webhook: Subscription already exists in database (id: {}), skipping creation",
            existing.id
        );
        return Ok(());
    }
    let Some((reference_id, customer_type)) = find_reference(context, &customer_id).await? else {
        tracing::warn!(
            "Stripe webhook warning: No user or organization found with stripeCustomerId: {customer_id}"
        );
        return Ok(());
    };
    let plans = options.plans.plans().await?;
    let Some(resolved) = resolve_plan_item(&plans, &stripe_subscription.items.data) else {
        tracing::warn!(
            "Stripe webhook warning: Subscription {} has no items matching a configured plan",
            stripe_subscription.id
        );
        return Ok(());
    };
    let Some(plan) = resolved.plan else {
        tracing::warn!(
            "Stripe webhook warning: No matching plan found for priceId: {}",
            resolved.item.price.id
        );
        return Ok(());
    };
    let local = create_local(&stripe_subscription, resolved.item, plan, &reference_id);
    let local = context.store.create_subscription(local).await?;
    tracing::info!(
        "Stripe webhook: Created subscription {} for {} {} from dashboard",
        stripe_subscription.id,
        customer_type,
        reference_id
    );
    if let Some(callbacks) = &options.callbacks {
        callbacks
            .on_subscription_created(event, &stripe_subscription, &local, plan)
            .await?;
    }
    Ok(())
}

async fn find_duplicate(
    context: LifecycleContext<'_>,
    stripe_subscription: &StripeSubscription,
) -> Result<Option<Subscription>, LifecycleError> {
    if let Some(id) = metadata_string(&stripe_subscription.metadata, "subscriptionId") {
        return match id.parse::<Uuid>() {
            Ok(id) => Ok(context.store.find_subscription(id).await?),
            Err(_) => Ok(None),
        };
    }
    Ok(context
        .store
        .find_subscription_by_stripe_id(&stripe_subscription.id)
        .await?)
}

fn create_local(
    stripe_subscription: &StripeSubscription,
    item: &crate::stripe::StripeSubscriptionItem,
    plan: &StripePlan,
    reference_id: &str,
) -> Subscription {
    let trial = trial_timestamp(
        stripe_subscription.trial_start,
        stripe_subscription.trial_end,
    );
    Subscription {
        id: Uuid::new_v4(),
        plan: plan.persisted_name(),
        reference_id: reference_id.to_owned(),
        stripe_customer_id: customer_to_string(&stripe_subscription.customer),
        stripe_subscription_id: Some(stripe_subscription.id.clone()),
        status: stripe_subscription.status,
        period_start: timestamp(item.current_period_start),
        period_end: timestamp(item.current_period_end),
        trial_start: trial.map(|(start, _)| start),
        trial_end: trial.map(|(_, end)| end),
        cancel_at_period_end: false,
        cancel_at: None,
        canceled_at: None,
        ended_at: None,
        seats: Some(resolve_quantity(stripe_subscription, item, plan)),
        billing_interval: item.price.recurring.as_ref().map(|value| value.interval),
        stripe_schedule_id: None,
    }
}

async fn find_reference(
    context: LifecycleContext<'_>,
    stripe_customer_id: &str,
) -> Result<Option<(String, &'static str)>, LifecycleError> {
    if context.options.organization.is_some()
        && let Some(id) = context
            .store
            .organization_id_by_customer(stripe_customer_id)
            .await?
    {
        return Ok(Some((id.to_string(), "organization")));
    }
    Ok(context
        .store
        .user_id_by_customer(stripe_customer_id)
        .await?
        .map(|id| (id.to_string(), "user")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stripe::webhook::test_support::{
        FakeStripeClient, enabled_options, event, provider_subscription,
    };
    use crate::stripe::{MemoryStripeStore, OrganizationOptions, StripeStore, SubscriptionStatus};
    use std::sync::Arc;

    #[tokio::test]
    async fn dashboard_creation_prefers_organization_and_suppresses_targeted_duplicates() {
        let provider = provider_subscription(SubscriptionStatus::Active);
        let webhook = event(
            "customer.subscription.created",
            serde_json::to_value(&provider).unwrap(),
        );
        let client = Arc::new(FakeStripeClient::new(webhook.clone()));
        let mut options = enabled_options(client);
        options.organization = Some(OrganizationOptions {
            get_customer_create_params: None,
            on_customer_create: None,
        });
        let store = MemoryStripeStore::new();
        let user_id = Uuid::new_v4();
        let organization_id = Uuid::new_v4();
        store
            .set_user_customer_id(&user_id.to_string(), Some("cus_1".into()))
            .await
            .unwrap();
        store
            .set_organization_customer_id(organization_id, Some("cus_1".into()))
            .await
            .unwrap();
        let context = LifecycleContext {
            options: &options,
            store: &store,
        };

        handle(context, &webhook).await.unwrap();
        handle(context, &webhook).await.unwrap();

        let rows = store
            .list_subscriptions(&organization_id.to_string())
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reference_id, organization_id.to_string());
        assert!(
            store
                .list_subscriptions(&user_id.to_string())
                .await
                .unwrap()
                .is_empty()
        );
    }
}
