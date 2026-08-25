use super::PostgresStore;
use crate::oauth_provider::{
    OAuthProviderConfigError, OAuthProviderSchema, schema::ResolvedOAuthProviderSchema,
};
use sqlx::PgPool;

mod assertion;
mod client;
mod consent;
mod resource;
mod rows;
mod token;

/// PostgreSQL persistence for one OAuth Provider plugin schema mapping.
#[derive(Clone)]
pub struct PostgresOAuthProviderStore {
    store: PostgresStore,
    schema: ResolvedOAuthProviderSchema,
    migration_sql: String,
}

impl PostgresOAuthProviderStore {
    pub fn new(
        store: PostgresStore,
        schema: &OAuthProviderSchema,
    ) -> Result<Self, OAuthProviderConfigError> {
        let schema = ResolvedOAuthProviderSchema::new(schema)?;
        let migration_sql = schema.migration_sql();
        Ok(Self {
            store,
            schema,
            migration_sql,
        })
    }

    /// SQL that creates the tables, constraints, and indexes for this mapping.
    pub fn migration_sql(&self) -> &str {
        &self.migration_sql
    }

    fn pool(&self) -> &PgPool {
        &self.store.pool
    }
}
