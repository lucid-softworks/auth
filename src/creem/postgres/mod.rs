use super::{
    CreemSchema, CreemSchemaError, CreemStore, CreemStoreError, CreemStoredUser, CreemSubscription,
    CreemSubscriptionPatch, schema::ResolvedCreemSchema,
};
use crate::postgres::PostgresStore;
use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

mod rows;
mod subscription;
mod user;

/// PostgreSQL persistence for one isolated Creem schema mapping.
#[derive(Clone)]
pub struct PostgresCreemStore {
    store: PostgresStore,
    schema: ResolvedCreemSchema,
    migration_sql: String,
}

impl PostgresCreemStore {
    pub fn new(
        store: PostgresStore,
        schema: &CreemSchema,
        persist_subscriptions: bool,
    ) -> Result<Self, CreemSchemaError> {
        let schema = ResolvedCreemSchema::new(schema, persist_subscriptions)?;
        let migration_sql = schema.migration_sql();
        Ok(Self {
            store,
            schema,
            migration_sql,
        })
    }

    pub fn migration_sql(&self) -> &str {
        &self.migration_sql
    }

    fn pool(&self) -> &PgPool {
        self.store.pool()
    }
}

#[async_trait]
impl CreemStore for PostgresCreemStore {
    async fn find_user(
        &self,
        reference_id: &str,
    ) -> Result<Option<CreemStoredUser>, CreemStoreError> {
        user::find(self, reference_id).await
    }

    async fn set_user_customer_id(
        &self,
        reference_id: &str,
        customer_id: &str,
    ) -> Result<(), CreemStoreError> {
        user::set_customer_id(self, reference_id, customer_id).await
    }

    async fn set_user_had_trial(
        &self,
        reference_id: &str,
        had_trial: bool,
    ) -> Result<(), CreemStoreError> {
        user::set_had_trial(self, reference_id, had_trial).await
    }

    async fn create_subscription(
        &self,
        subscription: CreemSubscription,
    ) -> Result<CreemSubscription, CreemStoreError> {
        subscription::create(self, subscription).await
    }

    async fn find_subscription_by_creem_id(
        &self,
        creem_subscription_id: &str,
    ) -> Result<Option<CreemSubscription>, CreemStoreError> {
        subscription::find_by_creem_id(self, creem_subscription_id).await
    }

    async fn list_subscriptions_by_reference(
        &self,
        reference_id: &str,
    ) -> Result<Vec<CreemSubscription>, CreemStoreError> {
        subscription::list_by_reference(self, reference_id).await
    }

    async fn list_subscriptions_by_customer(
        &self,
        creem_customer_id: &str,
    ) -> Result<Vec<CreemSubscription>, CreemStoreError> {
        subscription::list_by_customer(self, creem_customer_id).await
    }

    async fn update_subscription(
        &self,
        id: Uuid,
        patch: CreemSubscriptionPatch,
    ) -> Result<Option<CreemSubscription>, CreemStoreError> {
        subscription::update(self, id, patch).await
    }
}

fn storage_error(error: sqlx::Error) -> CreemStoreError {
    if error
        .as_database_error()
        .and_then(|database| database.code())
        .as_deref()
        == Some("23505")
    {
        CreemStoreError::DuplicateId
    } else {
        CreemStoreError::Unavailable(error.to_string())
    }
}
