use crate::{
    AdditionalField, AdditionalFieldReference, AdditionalFieldType, AuthConfig, AuthSchemaCatalog,
    DatabaseIdType, PluginSchemaTable,
    postgres::{PostgresAdapterConfig, PostgresStore},
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

#[tokio::test]
async fn plural_runtime_shadow_does_not_block_raw_plugin_table_binding() {
    let config = AuthConfig::new([45; 32]).unwrap();
    let catalog = Arc::new(
        AuthSchemaCatalog::build(
            &config,
            [
                PluginSchemaTable::new("users")
                    .model_name("pluginOnly")
                    .id_type(DatabaseIdType::String)
                    .field(
                        "pluginValue",
                        AdditionalField::new(AdditionalFieldType::String)
                            .field_name("plugin field"),
                    ),
                PluginSchemaTable::new("pluginChild").field(
                    "ownerId",
                    AdditionalField::new(AdditionalFieldType::String).references(
                        AdditionalFieldReference {
                            model: "users".into(),
                            field: "id".into(),
                            on_delete: None,
                        },
                    ),
                ),
            ],
        )
        .unwrap(),
    );
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://localhost/plural_collision_test")
        .unwrap();
    let store = PostgresStore::new(pool, PostgresAdapterConfig { use_plural: true });

    store.bind_catalog(catalog).unwrap();

    let resolved = store.resolved_schema().unwrap();
    assert_eq!(resolved.default_model_name("users").unwrap(), "user");
    assert_eq!(resolved.model_name("users").unwrap(), "users");
    assert!(resolved.field_name("users", "pluginValue").is_err());

    let runtime_users = store.physical_model("users").unwrap();
    assert_eq!(runtime_users.table(), "users");
    assert!(runtime_users.has_field("name"));
    assert!(!runtime_users.has_field("pluginValue"));

    let sql = store
        .physical_schema()
        .unwrap()
        .migration_sql(resolved)
        .unwrap();
    assert!(sql.contains("CREATE TABLE \"users\""));
    assert!(sql.contains("CREATE TABLE \"pluginOnlys\""));
    assert!(sql.contains("\"plugin field\" TEXT NOT NULL"));
    assert!(sql.contains(
        "\"ownerId\" TEXT NOT NULL REFERENCES \"pluginOnlys\"(\"id\") ON DELETE CASCADE"
    ));
}
