use super::PostgresStore;
use crate::device_authorization::{
    DeviceAuthorizationConfigError, DeviceAuthorizationSchema,
    schema::ResolvedDeviceAuthorizationSchema,
};
use sqlx::PgPool;

mod rows;
mod store;

/// PostgreSQL persistence for one Device Authorization plugin schema mapping.
#[derive(Clone)]
pub struct PostgresDeviceAuthorizationStore {
    store: PostgresStore,
    schema: ResolvedDeviceAuthorizationSchema,
    oauth_mode: bool,
    migration_sql: String,
}

impl PostgresDeviceAuthorizationStore {
    pub fn new(
        store: PostgresStore,
        schema: &DeviceAuthorizationSchema,
        oauth_mode: bool,
    ) -> Result<Self, DeviceAuthorizationConfigError> {
        let schema = ResolvedDeviceAuthorizationSchema::new(schema, oauth_mode)?;
        let migration_sql = schema.migration_sql();
        Ok(Self {
            store,
            schema,
            oauth_mode,
            migration_sql,
        })
    }

    /// SQL that creates the remapped device-code table and unique indexes.
    pub fn migration_sql(&self) -> &str {
        &self.migration_sql
    }

    fn pool(&self) -> &PgPool {
        &self.store.pool
    }
}
