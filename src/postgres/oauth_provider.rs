use super::PostgresStore;
use crate::{AuthError, postgres::PostgresModel};
use sqlx::PgPool;

mod assertion;
mod client;
mod consent;
mod resource;
mod rows;
mod token;

/// PostgreSQL persistence through the schema bound to the parent auth service.
#[derive(Clone)]
pub struct PostgresOAuthProviderStore {
    store: PostgresStore,
}

impl PostgresOAuthProviderStore {
    pub fn new(store: PostgresStore) -> Self {
        Self { store }
    }

    fn model(&self, logical: &str) -> Result<PostgresModel<'_>, AuthError> {
        self.store.physical_model(logical)
    }

    fn pool(&self) -> &PgPool {
        &self.store.pool
    }
}
