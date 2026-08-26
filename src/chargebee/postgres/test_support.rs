use super::PostgresChargebeeStore;
use crate::{
    AuthConfig, AuthSchemaCatalog, AuthStore,
    chargebee::chargebee_schema_tables,
    postgres::{PostgresAdapterConfig, PostgresStore},
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

pub(super) fn store() -> PostgresChargebeeStore {
    let mut auth = AuthConfig::new([53; 32]).unwrap();
    auth.user.model_name = Some("chargebee\"users".into());
    let mut tables = chargebee_schema_tables(true, true);
    for table in &mut tables {
        table.model_name = Some(format!("chargebee\"{}", table.logical_name));
        for (logical, field) in &mut table.fields {
            field.field_name = Some(format!("physical {logical}"));
        }
    }
    let catalog = Arc::new(AuthSchemaCatalog::build(&auth, tables).unwrap());
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://localhost/lucid_auth")
        .unwrap();
    let postgres = PostgresStore::new(pool, PostgresAdapterConfig { use_plural: true });
    postgres.bind_schema(catalog).unwrap();
    PostgresChargebeeStore::new(postgres)
}
