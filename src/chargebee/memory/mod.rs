mod customer;
mod item;
mod subscription;

use super::{
    ChargebeeStore, ChargebeeStoreError, ChargebeeSubscription, ChargebeeSubscriptionItem,
    ChargebeeSubscriptionPatch,
};
use crate::AuthStore;
use async_trait::async_trait;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

#[derive(Default)]
pub(super) struct MemoryChargebeeState {
    pub(super) organizations: BTreeMap<Uuid, String>,
    pub(super) subscriptions: BTreeMap<Uuid, ChargebeeSubscription>,
    pub(super) subscription_order: Vec<Uuid>,
    pub(super) items: BTreeMap<Uuid, ChargebeeSubscriptionItem>,
    pub(super) item_order: Vec<Uuid>,
}

/// In-memory Chargebee state attached to the same user store as AuthService.
pub struct MemoryChargebeeStore {
    pub(super) auth_store: Arc<dyn AuthStore>,
    pub(super) customer_write: Mutex<()>,
    pub(super) state: RwLock<MemoryChargebeeState>,
}

impl MemoryChargebeeStore {
    pub fn new(auth_store: Arc<dyn AuthStore>) -> Self {
        Self {
            auth_store,
            customer_write: Mutex::new(()),
            state: RwLock::new(MemoryChargebeeState::default()),
        }
    }
}

#[async_trait]
impl ChargebeeStore for MemoryChargebeeStore {
    async fn user_customer_id(&self, user_id: Uuid) -> Result<Option<String>, ChargebeeStoreError> {
        customer::user_customer_id(self, user_id).await
    }

    async fn set_user_customer_id(
        &self,
        user_id: Uuid,
        customer_id: Option<String>,
    ) -> Result<(), ChargebeeStoreError> {
        customer::set_user_customer_id(self, user_id, customer_id).await
    }

    async fn user_id_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<Uuid>, ChargebeeStoreError> {
        customer::user_id_by_customer(self, customer_id).await
    }

    async fn organization_customer_id(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<String>, ChargebeeStoreError> {
        customer::organization_customer_id(self, organization_id).await
    }

    async fn set_organization_customer_id(
        &self,
        organization_id: Uuid,
        customer_id: Option<String>,
    ) -> Result<(), ChargebeeStoreError> {
        customer::set_organization_customer_id(self, organization_id, customer_id).await
    }

    async fn organization_id_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<Uuid>, ChargebeeStoreError> {
        customer::organization_id_by_customer(self, customer_id).await
    }

    async fn create_subscription(
        &self,
        value: ChargebeeSubscription,
    ) -> Result<ChargebeeSubscription, ChargebeeStoreError> {
        subscription::create(self, value).await
    }

    async fn find_subscription(
        &self,
        id: Uuid,
    ) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
        subscription::find(self, id).await
    }

    async fn find_subscription_by_chargebee_id(
        &self,
        id: &str,
    ) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
        subscription::find_by_chargebee_id(self, id).await
    }

    async fn list_subscriptions_by_reference(
        &self,
        reference_id: &str,
    ) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
        subscription::list_by_reference(self, reference_id).await
    }

    async fn list_subscriptions_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
        subscription::list_by_customer(self, customer_id).await
    }

    async fn update_subscription(
        &self,
        id: Uuid,
        patch: ChargebeeSubscriptionPatch,
    ) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
        subscription::update(self, id, patch).await
    }

    async fn delete_subscription(
        &self,
        id: Uuid,
    ) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
        subscription::delete(self, id).await
    }

    async fn delete_subscriptions_by_reference(
        &self,
        reference_id: &str,
    ) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
        subscription::delete_by_reference(self, reference_id).await
    }

    async fn delete_subscriptions_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
        subscription::delete_by_customer(self, customer_id).await
    }

    async fn create_subscription_item(
        &self,
        value: ChargebeeSubscriptionItem,
    ) -> Result<ChargebeeSubscriptionItem, ChargebeeStoreError> {
        item::create(self, value).await
    }

    async fn list_subscription_items(
        &self,
        subscription_id: Uuid,
    ) -> Result<Vec<ChargebeeSubscriptionItem>, ChargebeeStoreError> {
        item::list(self, subscription_id).await
    }

    async fn delete_subscription_items(
        &self,
        subscription_id: Uuid,
    ) -> Result<Vec<ChargebeeSubscriptionItem>, ChargebeeStoreError> {
        item::delete(self, subscription_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthUser, ChargebeeItemType, ChargebeeSubscriptionStatus, MemoryStore};
    use chrono::Utc;
    use serde_json::Map;

    #[tokio::test]
    async fn customer_ids_are_unique_in_each_conditional_owner_model() {
        let auth_store = Arc::new(MemoryStore::default());
        let first_user = user();
        let second_user = user();
        auth_store
            .create_user_without_account(first_user.clone())
            .await
            .unwrap();
        auth_store
            .create_user_without_account(second_user.clone())
            .await
            .unwrap();
        let store = MemoryChargebeeStore::new(auth_store);

        store
            .set_user_customer_id(first_user.id, Some("customer_user".into()))
            .await
            .unwrap();
        assert_eq!(
            store.user_id_by_customer("customer_user").await.unwrap(),
            Some(first_user.id)
        );
        assert_eq!(
            store
                .set_user_customer_id(second_user.id, Some("customer_user".into()))
                .await,
            Err(ChargebeeStoreError::DuplicateCustomerId)
        );

        let first_organization = Uuid::new_v4();
        let second_organization = Uuid::new_v4();
        store
            .set_organization_customer_id(first_organization, Some("customer_org".into()))
            .await
            .unwrap();
        assert_eq!(
            store
                .set_organization_customer_id(second_organization, Some("customer_org".into()))
                .await,
            Err(ChargebeeStoreError::DuplicateCustomerId)
        );
    }

    #[tokio::test]
    async fn references_are_nonunique_provider_ids_are_unique_and_order_is_stable() {
        let store = MemoryChargebeeStore::new(Arc::new(MemoryStore::default()));
        let first = subscription("shared", Some("provider_first"));
        let second = subscription("shared", Some("provider_second"));
        store.create_subscription(first.clone()).await.unwrap();
        store.create_subscription(second.clone()).await.unwrap();
        assert_eq!(
            store
                .list_subscriptions_by_reference("shared")
                .await
                .unwrap()
                .into_iter()
                .map(|subscription| subscription.id)
                .collect::<Vec<_>>(),
            [first.id, second.id]
        );

        let duplicate = subscription("other", Some("provider_first"));
        assert_eq!(
            store.create_subscription(duplicate).await,
            Err(ChargebeeStoreError::DuplicateSubscriptionId)
        );
    }

    #[tokio::test]
    async fn items_are_sequential_and_subscription_deletion_cascades() {
        let store = MemoryChargebeeStore::new(Arc::new(MemoryStore::default()));
        let subscription = subscription("owner", None);
        store
            .create_subscription(subscription.clone())
            .await
            .unwrap();
        let plan = ChargebeeSubscriptionItem::new(
            subscription.id,
            "plan_price",
            ChargebeeItemType::Plan,
            1.0,
        );
        let addon = ChargebeeSubscriptionItem::new(
            subscription.id,
            "addon_price",
            ChargebeeItemType::Addon,
            2.0,
        );
        store.create_subscription_item(plan.clone()).await.unwrap();
        store.create_subscription_item(addon.clone()).await.unwrap();
        assert_eq!(
            store
                .list_subscription_items(subscription.id)
                .await
                .unwrap(),
            [plan, addon]
        );

        store.delete_subscription(subscription.id).await.unwrap();
        assert!(
            store
                .list_subscription_items(subscription.id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    fn subscription(reference_id: &str, provider_id: Option<&str>) -> ChargebeeSubscription {
        let mut subscription = ChargebeeSubscription::future(reference_id);
        subscription.chargebee_subscription_id = provider_id.map(str::to_owned);
        subscription.status = ChargebeeSubscriptionStatus::Future;
        subscription
    }

    fn user() -> AuthUser {
        let now = Utc::now();
        AuthUser {
            id: Uuid::new_v4(),
            username: None,
            display_username: None,
            name: "Chargebee user".into(),
            email: format!("{}@example.test", Uuid::new_v4()),
            email_verified: true,
            image: None,
            additional_fields: Map::new(),
            role: "user".into(),
            is_anonymous: false,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            created_at: now,
            updated_at: now,
        }
    }
}
