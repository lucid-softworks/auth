use super::{StripeStore, StripeStoreError, Subscription, SubscriptionPatch};
use crate::{
    AuthError,
    postgres::{PostgresModel, PostgresStore},
};
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

mod customer;
mod rows;
mod subscription;

#[cfg(test)]
mod test_support;

/// PostgreSQL persistence for one resolved Stripe plugin schema mapping.
#[derive(Clone)]
pub struct PostgresStripeStore {
    store: PostgresStore,
}

impl PostgresStripeStore {
    pub fn new(store: PostgresStore) -> Self {
        Self { store }
    }

    fn pool(&self) -> &PgPool {
        self.store.pool()
    }

    fn model(&self, logical: &str) -> Result<PostgresModel<'_>, StripeStoreError> {
        self.store.physical_model(logical).map_err(schema_error)
    }

    fn model_if_present(
        &self,
        logical: &str,
    ) -> Result<Option<PostgresModel<'_>>, StripeStoreError> {
        self.store
            .physical_model_if_present(logical)
            .map_err(schema_error)
    }
}

fn schema_error(error: AuthError) -> StripeStoreError {
    StripeStoreError::Unavailable(error.to_string())
}

#[async_trait]
impl StripeStore for PostgresStripeStore {
    async fn user_customer_id(&self, user_id: &str) -> Result<Option<String>, StripeStoreError> {
        customer::user_customer_id(self, user_id).await
    }

    async fn set_user_customer_id(
        &self,
        user_id: &str,
        customer_id: Option<String>,
    ) -> Result<(), StripeStoreError> {
        customer::set_user_customer_id(self, user_id, customer_id).await
    }

    async fn user_id_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<String>, StripeStoreError> {
        customer::user_id_by_customer(self, customer_id).await
    }

    async fn organization_customer_id(
        &self,
        organization_id: &str,
    ) -> Result<Option<String>, StripeStoreError> {
        customer::organization_customer_id(self, organization_id).await
    }

    async fn set_organization_customer_id(
        &self,
        organization_id: String,
        customer_id: Option<String>,
    ) -> Result<(), StripeStoreError> {
        customer::set_organization_customer_id(self, organization_id, customer_id).await
    }

    async fn organization_id_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<String>, StripeStoreError> {
        customer::organization_id_by_customer(self, customer_id).await
    }

    async fn create_subscription(
        &self,
        subscription: Subscription,
    ) -> Result<Subscription, StripeStoreError> {
        subscription::create(self, subscription).await
    }

    async fn find_subscription(&self, id: Uuid) -> Result<Option<Subscription>, StripeStoreError> {
        subscription::find(self, id).await
    }

    async fn find_subscription_by_stripe_id(
        &self,
        stripe_subscription_id: &str,
    ) -> Result<Option<Subscription>, StripeStoreError> {
        subscription::find_by_stripe_id(self, stripe_subscription_id).await
    }

    async fn list_subscriptions(
        &self,
        reference_id: &str,
    ) -> Result<Vec<Subscription>, StripeStoreError> {
        subscription::list(self, reference_id).await
    }

    async fn list_subscriptions_by_customer(
        &self,
        stripe_customer_id: &str,
    ) -> Result<Vec<Subscription>, StripeStoreError> {
        subscription::list_by_customer(self, stripe_customer_id).await
    }

    async fn find_active_subscription_by_customer(
        &self,
        stripe_customer_id: &str,
    ) -> Result<Option<Subscription>, StripeStoreError> {
        subscription::find_active_by_customer(self, stripe_customer_id).await
    }

    async fn update_subscription(
        &self,
        id: Uuid,
        patch: SubscriptionPatch,
    ) -> Result<Option<Subscription>, StripeStoreError> {
        subscription::update(self, id, patch).await
    }

    async fn delete_subscription(
        &self,
        id: Uuid,
    ) -> Result<Option<Subscription>, StripeStoreError> {
        subscription::delete(self, id).await
    }
}

fn storage_error(error: sqlx::Error) -> StripeStoreError {
    if error
        .as_database_error()
        .and_then(|database| database.code())
        .as_deref()
        == Some("23505")
    {
        StripeStoreError::DuplicateId
    } else {
        StripeStoreError::Unavailable(error.to_string())
    }
}
