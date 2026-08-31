use crate::{
    AdditionalField, AdditionalFieldType, AdapterSchemaOptions, AuthConfig, AuthSchemaCatalog,
    PluginSchemaTable, ResolvedAdapterSchema,
    mysql::{
        MySqlAdapterConfig, MySqlComparisonMode, MySqlFilter, MySqlFilterConnector,
        MySqlFilterOperator, MySqlMigrationMode, MySqlStore,
    },
};
use serde_json::{Map, Value, json};
use sqlx::{MySqlPool, Row, mysql::MySqlPoolOptions};
use std::sync::Arc;

fn counter() -> PluginSchemaTable {
    PluginSchemaTable::new("counter")
        .field(
            "name",
            AdditionalField::new(AdditionalFieldType::String).unique(true),
        )
        .field(
            "value",
            AdditionalField::new(AdditionalFieldType::Number),
        )
        .field(
            "active",
            AdditionalField::new(AdditionalFieldType::Boolean),
        )
        .field(
            "when",
            AdditionalField::new(AdditionalFieldType::Date),
        )
        .field(
            "metadata",
            AdditionalField::new(AdditionalFieldType::Json),
        )
        .field(
            "tags",
            AdditionalField::new(AdditionalFieldType::StringArray),
        )
        .field(
            "note",
            AdditionalField::new(AdditionalFieldType::String).optional(),
        )
}

fn catalog(table: PluginSchemaTable, serial: bool) -> Arc<AuthSchemaCatalog> {
    let mut config = AuthConfig::new([62; 32]).unwrap();
    if serial {
        config.database_id_generation = crate::DatabaseIdGeneration::Serial;
    }
    Arc::new(AuthSchemaCatalog::build(&config, [table]).unwrap())
}

fn record(id: Option<&str>, name: &str, value: i64) -> Map<String, Value> {
    let mut record = Map::from_iter([
        ("name".into(), json!(name)),
        ("value".into(), json!(value)),
        ("active".into(), json!(true)),
        ("when".into(), json!("2026-08-31T12:34:56.123456Z")),
        ("metadata".into(), json!({"nested": true})),
        ("tags".into(), json!(["one", "two"])),
        ("note".into(), Value::Null),
    ]);
    if let Some(id) = id {
        record.insert("id".into(), json!(id));
    }
    record
}

async fn fixture() -> (MySqlPool, MySqlStore) {
    let url = std::env::var("MYSQL_DATABASE_URL")
        .unwrap_or_else(|_| "mysql://lucid:lucid@127.0.0.1:3307/lucid_auth_test".into());
    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .unwrap();
    reset(&pool).await;
    let store = MySqlStore::new(pool.clone(), MySqlAdapterConfig::default());
    store.ready().await.unwrap();
    (pool, store)
}

async fn reset(pool: &MySqlPool) {
    sqlx::query("set foreign_key_checks = 0")
        .execute(pool)
        .await
        .unwrap();
    let tables = sqlx::query(
        "select cast(table_name as char) from information_schema.tables where table_schema = database() and table_type = 'BASE TABLE'",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    for row in tables {
        let table: String = row.try_get(0).unwrap();
        let sql = format!("drop table {}", crate::mysql::schema::quote(&table));
        sqlx::query(&sql).execute(pool).await.unwrap();
    }
    sqlx::query("set foreign_key_checks = 1")
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires the pinned MySQL integration fixture"]
async fn migrates_round_trips_and_preserves_atomic_mutations() {
    let (_pool, store) = fixture().await;
    let schema = catalog(counter(), false);
    let plan = store.migrate(schema.clone()).await.unwrap();
    assert!(plan.steps().count() > 0);
    assert_eq!(
        store
            .migration_plan(schema, MySqlMigrationMode::Compile)
            .await
            .unwrap()
            .compiled_sql(),
        ";"
    );

    let inserted = store
        .insert_record("counter", record(Some("one"), "Alpha", 4))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inserted["when"], json!("2026-08-31T12:34:56.123Z"));
    assert_eq!(inserted["metadata"], json!({"nested": true}));
    assert_eq!(inserted["tags"], json!(["one", "two"]));

    let insensitive = MySqlFilter {
        field: "name".into(),
        value: json!("ALP"),
        operator: MySqlFilterOperator::Contains,
        connector: MySqlFilterConnector::And,
        mode: MySqlComparisonMode::Insensitive,
    };
    assert_eq!(store.count_records("counter", &[insensitive]).await.unwrap(), 1);
    let id = [MySqlFilter::equal("id", json!("one"))];
    assert!(
        store
            .update_record(
                "counter",
                &id,
                Map::from_iter([("name".into(), json!("Alpha"))]),
            )
            .await
            .unwrap()
            .is_some(),
        "FOUND_ROWS keeps an idempotent matched update successful"
    );
    let updated = store
        .increment_record(
            "counter",
            &id,
            Map::from_iter([("value".into(), json!(3))]),
            Map::from_iter([("note".into(), json!("updated"))]),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated["value"], json!(7));
    assert!(store.consume_record("counter", &id).await.unwrap().is_some());
    assert!(store.consume_record("counter", &id).await.unwrap().is_none());
}

#[tokio::test]
#[ignore = "requires the pinned MySQL integration fixture"]
async fn uses_connection_local_serial_ids_and_rolls_back() {
    let (pool, store) = fixture().await;
    let schema = catalog(counter(), true);
    store.migrate(schema).await.unwrap();
    let inserted = store
        .insert_record("counter", record(None, "Serial", 1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inserted["id"], json!("1"));

    let mut transaction = store.begin().await.unwrap();
    transaction
        .insert_record("counter", record(None, "Rollback", 2))
        .await
        .unwrap();
    transaction.rollback().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from `counter` where `name` = 'Rollback'")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
}

#[test]
fn physical_schema_uses_the_shared_resolver() {
    let resolved = ResolvedAdapterSchema::new(
        catalog(counter(), false),
        AdapterSchemaOptions::default(),
    )
    .unwrap();
    assert_eq!(resolved.model_name("counter").unwrap(), "counter");
}
