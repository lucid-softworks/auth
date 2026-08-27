use crate::{
    Organization, OrganizationStore, StripePlan, StripePlugin, StripeProviderError,
    StripeStoreError, Subscription, SubscriptionPatch,
};
use serde_json::json;

pub(super) async fn sync(
    plugin: &StripePlugin,
    organization: &Organization,
    organization_store: &dyn OrganizationStore,
) {
    if !plugin.subscriptions_enabled() {
        return;
    }
    let result = sync_inner(plugin, organization, organization_store).await;
    if let Err(error) = result {
        tracing::error!("Failed to sync seats to Stripe: {error}");
    }
}

async fn sync_inner(
    plugin: &StripePlugin,
    organization: &Organization,
    organization_store: &dyn OrganizationStore,
) -> Result<(), SeatSyncError> {
    let Some(_customer_id) = plugin
        .store
        .organization_customer_id(&organization.id)
        .await?
    else {
        return Ok(());
    };
    let member_count = organization_store
        .list_members(&organization.id)
        .await?
        .len() as f64;
    let Some((subscription, plan)) = local_seat_subscription(plugin, organization).await? else {
        return Ok(());
    };
    update_quantity(plugin, subscription, plan, member_count).await
}

async fn local_seat_subscription(
    plugin: &StripePlugin,
    organization: &Organization,
) -> Result<Option<(Subscription, StripePlan)>, SeatSyncError> {
    let seat_plans = plugin
        .options
        .plans()
        .await?
        .into_iter()
        .filter(|plan| plan.seat_price_id.is_some())
        .collect::<Vec<_>>();
    if seat_plans.is_empty() {
        return Ok(None);
    }
    let Some(subscription) = plugin
        .store
        .list_subscriptions(&organization.id.to_string())
        .await?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    if !subscription.is_active_or_trialing() {
        return Ok(None);
    }
    let Some(plan) = seat_plans
        .into_iter()
        .find(|plan| plan.persisted_name() == subscription.plan)
    else {
        return Ok(None);
    };
    Ok(Some((subscription, plan)))
}

async fn update_quantity(
    plugin: &StripePlugin,
    subscription: Subscription,
    plan: StripePlan,
    member_count: f64,
) -> Result<(), SeatSyncError> {
    let Some(stripe_subscription_id) = subscription.stripe_subscription_id.as_deref() else {
        return Ok(());
    };
    let stripe_subscription = plugin
        .options
        .client
        .retrieve_subscription(stripe_subscription_id)
        .await?;
    if !stripe_subscription.is_active_or_trialing() {
        return Ok(());
    }
    let seat_price_id = plan
        .seat_price_id
        .as_deref()
        .expect("the local plan was selected from seat plans");
    let seat_item = stripe_subscription
        .items
        .data
        .iter()
        .find(|item| item.price.id == seat_price_id);
    if seat_item.and_then(|item| item.quantity) == Some(member_count) {
        return Ok(());
    }
    let item = match seat_item {
        Some(item) => json!({ "id": item.id, "quantity": member_count }),
        None => json!({ "price": seat_price_id, "quantity": member_count }),
    };
    plugin
        .options
        .client
        .update_subscription(
            &stripe_subscription.id,
            json!({
                "items": [item],
                "proration_behavior": plan.proration_behavior.as_str()
            }),
        )
        .await?;
    plugin
        .store
        .update_subscription(
            subscription.id,
            SubscriptionPatch {
                seats: Some(Some(member_count)),
                ..SubscriptionPatch::default()
            },
        )
        .await?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum SeatSyncError {
    #[error(transparent)]
    Auth(#[from] crate::AuthError),
    #[error(transparent)]
    Store(#[from] StripeStoreError),
    #[error(transparent)]
    Provider(#[from] StripeProviderError),
    #[error(transparent)]
    Callback(#[from] crate::StripeCallbackError),
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{
        TestStripeClient, organization, plugin, provider_subscription,
    };
    use crate::*;
    use chrono::Utc;
    use std::sync::Arc;
    use uuid::Uuid;

    #[tokio::test]
    async fn member_changes_sync_provider_and_database_quantity() {
        let client = Arc::new(TestStripeClient::new());
        client
            .subscriptions
            .lock()
            .unwrap()
            .push(provider_subscription(SubscriptionStatus::Active));
        let stripe_store = Arc::new(MemoryStripeStore::new());
        let organization = organization();
        stripe_store
            .set_organization_customer_id(organization.id.clone(), Some("cus_org".into()))
            .await
            .unwrap();
        let now = Utc::now();
        let local = local_subscription(organization.id.clone());
        stripe_store
            .create_subscription(local.clone())
            .await
            .unwrap();
        let organization_store = MemoryOrganizationStore::default();
        let organization_id = organization.id.clone();
        let organization_id = || Ok(explicit_id(&organization_id));
        organization_store
            .raw_insert_organization(organization.clone(), &organization_id)
            .await
            .unwrap();
        for role in ["owner", "member"] {
            let member = OrganizationMember {
                id: Uuid::new_v4().to_string(),
                organization_id: organization.id.clone(),
                user_id: Uuid::new_v4().to_string(),
                role: role.into(),
                created_at: now,
            };
            let member_id = member.id.clone();
            let member_id = || Ok(explicit_id(&member_id));
            organization_store
                .raw_insert_member(member, &member_id)
                .await
                .unwrap();
        }
        plugin(client.clone(), stripe_store.clone(), true)
            .after_organization_member_change(&organization, &organization_store)
            .await;
        assert_eq!(
            client.subscription_updates.lock().unwrap().as_slice(),
            &[serde_json::json!({
                "items": [{ "id": "si_seat", "quantity": 2.0 }],
                "proration_behavior": "none"
            })]
        );
        assert_eq!(
            stripe_store
                .find_subscription(local.id)
                .await
                .unwrap()
                .unwrap()
                .seats,
            Some(2.0)
        );
    }

    fn explicit_id(value: &str) -> PreparedDatabaseId {
        PreparedDatabaseId::Value(DatabaseIdValue::String(value.into()))
    }

    fn local_subscription(organization_id: String) -> Subscription {
        Subscription {
            id: Uuid::new_v4(),
            plan: "team".into(),
            reference_id: organization_id,
            stripe_customer_id: Some("cus_org".into()),
            stripe_subscription_id: Some("sub_1".into()),
            status: SubscriptionStatus::Active,
            period_start: None,
            period_end: None,
            trial_start: None,
            trial_end: None,
            cancel_at_period_end: false,
            cancel_at: None,
            canceled_at: None,
            ended_at: None,
            seats: Some(1.0),
            billing_interval: None,
            stripe_schedule_id: None,
        }
    }
}
