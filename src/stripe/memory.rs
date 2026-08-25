use super::{StripeStore, StripeStoreError, Subscription, SubscriptionPatch};
use async_trait::async_trait;
use std::collections::BTreeMap;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Default)]
pub struct MemoryStripeStore {
    subscriptions: RwLock<BTreeMap<Uuid, Subscription>>,
    subscription_order: RwLock<Vec<Uuid>>,
    user_customers: RwLock<BTreeMap<Uuid, String>>,
    organization_customers: RwLock<BTreeMap<Uuid, String>>,
}

impl MemoryStripeStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl StripeStore for MemoryStripeStore {
    async fn user_customer_id(&self, user_id: Uuid) -> Result<Option<String>, StripeStoreError> {
        Ok(self.user_customers.read().await.get(&user_id).cloned())
    }

    async fn set_user_customer_id(
        &self,
        user_id: Uuid,
        customer_id: Option<String>,
    ) -> Result<(), StripeStoreError> {
        set_customer_id(&self.user_customers, user_id, customer_id).await;
        Ok(())
    }

    async fn user_id_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<Uuid>, StripeStoreError> {
        Ok(self
            .user_customers
            .read()
            .await
            .iter()
            .find_map(|(id, stored)| (stored == customer_id).then_some(*id)))
    }

    async fn organization_customer_id(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<String>, StripeStoreError> {
        Ok(self
            .organization_customers
            .read()
            .await
            .get(&organization_id)
            .cloned())
    }

    async fn set_organization_customer_id(
        &self,
        organization_id: Uuid,
        customer_id: Option<String>,
    ) -> Result<(), StripeStoreError> {
        set_customer_id(&self.organization_customers, organization_id, customer_id).await;
        Ok(())
    }

    async fn organization_id_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<Uuid>, StripeStoreError> {
        Ok(self
            .organization_customers
            .read()
            .await
            .iter()
            .find_map(|(id, stored)| (stored == customer_id).then_some(*id)))
    }

    async fn create_subscription(
        &self,
        subscription: Subscription,
    ) -> Result<Subscription, StripeStoreError> {
        let mut subscriptions = self.subscriptions.write().await;
        if subscriptions.contains_key(&subscription.id) {
            return Err(StripeStoreError::DuplicateId);
        }
        subscriptions.insert(subscription.id, subscription.clone());
        self.subscription_order.write().await.push(subscription.id);
        Ok(subscription)
    }

    async fn find_subscription(&self, id: Uuid) -> Result<Option<Subscription>, StripeStoreError> {
        Ok(self.subscriptions.read().await.get(&id).cloned())
    }

    async fn find_subscription_by_stripe_id(
        &self,
        stripe_subscription_id: &str,
    ) -> Result<Option<Subscription>, StripeStoreError> {
        Ok(self
            .subscriptions
            .read()
            .await
            .values()
            .find(|subscription| {
                subscription.stripe_subscription_id.as_deref() == Some(stripe_subscription_id)
            })
            .cloned())
    }

    async fn list_subscriptions(
        &self,
        reference_id: &str,
    ) -> Result<Vec<Subscription>, StripeStoreError> {
        let subscriptions = self.subscriptions.read().await;
        let order = self.subscription_order.read().await;
        Ok(order
            .iter()
            .filter_map(|id| subscriptions.get(id))
            .filter(|subscription| subscription.reference_id == reference_id)
            .cloned()
            .collect())
    }

    async fn find_active_subscription_by_customer(
        &self,
        stripe_customer_id: &str,
    ) -> Result<Option<Subscription>, StripeStoreError> {
        let subscriptions = self.subscriptions.read().await;
        let order = self.subscription_order.read().await;
        Ok(order
            .iter()
            .filter_map(|id| subscriptions.get(id))
            .find(|subscription| {
                subscription.stripe_customer_id.as_deref() == Some(stripe_customer_id)
                    && subscription.is_active_or_trialing()
            })
            .cloned())
    }

    async fn list_subscriptions_by_customer(
        &self,
        stripe_customer_id: &str,
    ) -> Result<Vec<Subscription>, StripeStoreError> {
        let subscriptions = self.subscriptions.read().await;
        let order = self.subscription_order.read().await;
        Ok(order
            .iter()
            .filter_map(|id| subscriptions.get(id))
            .filter(|subscription| {
                subscription.stripe_customer_id.as_deref() == Some(stripe_customer_id)
            })
            .cloned()
            .collect())
    }

    async fn update_subscription(
        &self,
        id: Uuid,
        patch: SubscriptionPatch,
    ) -> Result<Option<Subscription>, StripeStoreError> {
        let mut subscriptions = self.subscriptions.write().await;
        let Some(subscription) = subscriptions.get_mut(&id) else {
            return Ok(None);
        };
        patch.apply(subscription);
        Ok(Some(subscription.clone()))
    }

    async fn delete_subscription(
        &self,
        id: Uuid,
    ) -> Result<Option<Subscription>, StripeStoreError> {
        let removed = self.subscriptions.write().await.remove(&id);
        if removed.is_some() {
            self.subscription_order
                .write()
                .await
                .retain(|stored| *stored != id);
        }
        Ok(removed)
    }
}

async fn set_customer_id(
    customers: &RwLock<BTreeMap<Uuid, String>>,
    owner_id: Uuid,
    customer_id: Option<String>,
) {
    let mut customers = customers.write().await;
    if let Some(customer_id) = customer_id {
        customers.insert(owner_id, customer_id);
    } else {
        customers.remove(&owner_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stripe::SubscriptionStatus;
    use chrono::Utc;

    #[tokio::test]
    async fn reference_id_is_not_unique_and_adapter_order_is_stable() {
        let store = MemoryStripeStore::new();
        let first = subscription("shared");
        let second = subscription("shared");
        store.create_subscription(first.clone()).await.unwrap();
        store.create_subscription(second.clone()).await.unwrap();
        assert_eq!(
            store
                .list_subscriptions("shared")
                .await
                .unwrap()
                .into_iter()
                .map(|entry| entry.id)
                .collect::<Vec<_>>(),
            vec![first.id, second.id]
        );
    }

    #[tokio::test]
    async fn patches_can_clear_nullable_cancellation_and_schedule_fields() {
        let store = MemoryStripeStore::new();
        let mut record = subscription("user");
        record.cancel_at = Some(Utc::now());
        record.stripe_schedule_id = Some("sub_sched".into());
        store.create_subscription(record.clone()).await.unwrap();
        let updated = store
            .update_subscription(
                record.id,
                SubscriptionPatch {
                    cancel_at: Some(None),
                    stripe_schedule_id: Some(None),
                    ..SubscriptionPatch::default()
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert!(updated.cancel_at.is_none());
        assert!(updated.stripe_schedule_id.is_none());
    }

    fn subscription(reference_id: &str) -> Subscription {
        let now = Utc::now();
        Subscription {
            id: Uuid::new_v4(),
            plan: "pro".into(),
            reference_id: reference_id.into(),
            stripe_customer_id: None,
            stripe_subscription_id: None,
            status: SubscriptionStatus::Incomplete,
            period_start: None,
            period_end: None,
            trial_start: None,
            trial_end: None,
            cancel_at_period_end: false,
            cancel_at: None,
            canceled_at: None,
            ended_at: None,
            seats: None,
            billing_interval: None,
            stripe_schedule_id: None,
            created_at: now,
            updated_at: now,
        }
    }
}
