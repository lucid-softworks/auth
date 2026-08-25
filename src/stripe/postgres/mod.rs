use super::{
    StripeSchema, StripeSchemaError, StripeStore, StripeStoreError, Subscription,
    SubscriptionPatch, schema::ResolvedStripeSchema,
};
use crate::postgres::PostgresStore;
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

mod customer;
mod rows;
mod subscription;

/// PostgreSQL persistence for one resolved Stripe plugin schema mapping.
#[derive(Clone)]
pub struct PostgresStripeStore {
    store: PostgresStore,
    schema: ResolvedStripeSchema,
    migration_sql: String,
}

impl PostgresStripeStore {
    pub fn new(
        store: PostgresStore,
        schema: &StripeSchema,
        subscriptions_enabled: bool,
        organization_enabled: bool,
    ) -> Result<Self, StripeSchemaError> {
        let schema =
            ResolvedStripeSchema::new(schema, subscriptions_enabled, organization_enabled)?;
        let migration_sql = schema.migration_sql();
        Ok(Self {
            store,
            schema,
            migration_sql,
        })
    }

    /// SQL that creates the enabled, remapped Stripe persistence objects.
    pub fn migration_sql(&self) -> &str {
        &self.migration_sql
    }

    fn pool(&self) -> &PgPool {
        self.store.pool()
    }
}

#[async_trait]
impl StripeStore for PostgresStripeStore {
    async fn user_customer_id(&self, user_id: Uuid) -> Result<Option<String>, StripeStoreError> {
        customer::user_customer_id(self, user_id).await
    }

    async fn set_user_customer_id(
        &self,
        user_id: Uuid,
        customer_id: Option<String>,
    ) -> Result<(), StripeStoreError> {
        customer::set_user_customer_id(self, user_id, customer_id).await
    }

    async fn user_id_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<Uuid>, StripeStoreError> {
        customer::user_id_by_customer(self, customer_id).await
    }

    async fn organization_customer_id(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<String>, StripeStoreError> {
        customer::organization_customer_id(self, organization_id).await
    }

    async fn set_organization_customer_id(
        &self,
        organization_id: Uuid,
        customer_id: Option<String>,
    ) -> Result<(), StripeStoreError> {
        customer::set_organization_customer_id(self, organization_id, customer_id).await
    }

    async fn organization_id_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<Uuid>, StripeStoreError> {
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
