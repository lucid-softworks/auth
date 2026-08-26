use super::PostgresStore;
use sqlx::PgPool;

mod codec;
mod query;
mod store;

/// PostgreSQL persistence bound to the installed Device Authorization schema.
#[derive(Clone)]
pub struct PostgresDeviceAuthorizationStore {
    store: PostgresStore,
}

impl PostgresDeviceAuthorizationStore {
    pub fn new(store: PostgresStore) -> Self {
        Self { store }
    }

    fn pool(&self) -> &PgPool {
        &self.store.pool
    }

    fn model(&self) -> Result<super::PostgresModel<'_>, crate::AuthError> {
        self.store.physical_model("deviceCode")
    }
}
