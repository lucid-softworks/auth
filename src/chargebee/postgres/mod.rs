mod customer;
mod item;
mod rows;
mod subscription;

use super::{
    ChargebeeStore, ChargebeeStoreError, ChargebeeSubscription, ChargebeeSubscriptionItem,
    ChargebeeSubscriptionPatch,
};
use crate::postgres::PostgresStore;
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresChargebeeStore {
    store: PostgresStore,
    subscriptions_enabled: bool,
    organization_enabled: bool,
}

impl PostgresChargebeeStore {
    pub fn new(
        store: PostgresStore,
        subscriptions_enabled: bool,
        organization_enabled: bool,
    ) -> Self {
        Self {
            store,
            subscriptions_enabled,
            organization_enabled,
        }
    }

    fn pool(&self) -> &PgPool {
        self.store.pool()
    }
}

#[async_trait]
impl ChargebeeStore for PostgresChargebeeStore {
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

fn storage_error(error: sqlx::Error) -> ChargebeeStoreError {
    let database = error.as_database_error();
    match database.and_then(|error| error.constraint()) {
        Some(
            "lucid_auth_chargebee_user_customer_uidx"
            | "lucid_auth_chargebee_organization_customer_uidx",
        ) => ChargebeeStoreError::DuplicateCustomerId,
        Some("lucid_auth_chargebee_subscription_provider_uidx") => {
            ChargebeeStoreError::DuplicateSubscriptionId
        }
        _ if database.and_then(|error| error.code()).as_deref() == Some("23505") => {
            ChargebeeStoreError::DuplicateId
        }
        _ if database.and_then(|error| error.code()).as_deref() == Some("23503") => {
            ChargebeeStoreError::MissingSubscription
        }
        _ => ChargebeeStoreError::Unavailable(error.to_string()),
    }
}

fn subscriptions_disabled() -> ChargebeeStoreError {
    ChargebeeStoreError::Unavailable("Chargebee subscriptions are disabled".into())
}
