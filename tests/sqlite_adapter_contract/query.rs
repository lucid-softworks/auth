use crate::support::catalog;
use lucid_auth::{
    AdditionalField, AdditionalFieldType, AuthError, DashAdapterWhere, PluginSchemaTable,
    run_database_transaction,
    sqlite::{
        SqliteAdapterConfig, SqliteComparisonMode, SqliteFilter, SqliteFilterConnector,
        SqliteFilterOperator, SqliteMigrationMode, SqliteStore,
    },
};
use serde_json::{Map, Value, json};
use sqlx::sqlite::SqlitePoolOptions;

async fn store() -> SqliteStore {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = SqliteStore::new(pool, SqliteAdapterConfig::default());
    let table = PluginSchemaTable::new("counter")
        .field("name", AdditionalField::new(AdditionalFieldType::String))
        .field("value", AdditionalField::new(AdditionalFieldType::Number))
        .field("active", AdditionalField::new(AdditionalFieldType::Boolean))
        .field("when", AdditionalField::new(AdditionalFieldType::Date))
        .field("metadata", AdditionalField::new(AdditionalFieldType::Json))
        .field(
            "tags",
            AdditionalField::new(AdditionalFieldType::StringArray),
        )
        .field(
            "note",
            AdditionalField::new(AdditionalFieldType::String).optional(),
        );
    store.migrate(catalog(table, [62; 32])).await.unwrap();
    store
}

fn record(id: &str, name: &str, value: i64) -> Map<String, Value> {
    Map::from_iter([
        ("id".into(), json!(id)),
        ("name".into(), json!(name)),
        ("value".into(), json!(value)),
        ("active".into(), json!(true)),
        ("when".into(), json!("2026-08-27T12:34:56.123456Z")),
        ("metadata".into(), json!({"nested": true})),
        ("tags".into(), json!(["one", "two"])),
        ("note".into(), Value::Null),
    ])
}

#[tokio::test]
async fn round_trips_schema_values_and_bound_predicates() {
    let store = store().await;
    let inserted = store
        .insert_record("counter", record("one", "Alpha", 4))
        .await
        .unwrap();
    assert_eq!(inserted["when"], json!("2026-08-27T12:34:56.123Z"));
    assert_eq!(inserted["metadata"], json!({"nested": true}));
    assert_eq!(inserted["tags"], json!(["one", "two"]));

    let insensitive = SqliteFilter {
        field: "name".into(),
        value: json!("ALP"),
        operator: SqliteFilterOperator::Contains,
        connector: SqliteFilterConnector::And,
        mode: SqliteComparisonMode::Insensitive,
    };
    assert_eq!(
        store
            .count_records("counter", &[insensitive])
            .await
            .unwrap(),
        1
    );
    assert!(
        store
            .find_record(
                "counter",
                &[SqliteFilter::equal("missing", json!("value"))],
                &[],
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn atomic_increment_and_consume_return_each_row_once() {
    let store = store().await;
    store
        .insert_record("counter", record("one", "Alpha", 4))
        .await
        .unwrap();
    let filters = [SqliteFilter::equal("id", json!("one"))];
    let updated = store
        .increment_record(
            "counter",
            &filters,
            Map::from_iter([("value".into(), json!(3))]),
            Map::from_iter([("note".into(), json!("updated"))]),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated["value"], json!(7));
    assert_eq!(updated["note"], json!("updated"));
    assert!(
        store
            .consume_record("counter", &filters)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .consume_record("counter", &filters)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn explicit_transaction_rolls_back_without_store_policy() {
    let store = store().await;
    let mut transaction = store.begin().await.unwrap();
    transaction
        .insert_record("counter", record("rollback", "Temporary", 1))
        .await
        .unwrap();
    transaction.rollback().await.unwrap();
    assert!(
        store
            .find_record(
                "counter",
                &[SqliteFilter::equal("id", json!("rollback"))],
                &[],
            )
            .await
            .unwrap()
            .is_none()
    );

    let empty = store
        .migration_plan(
            catalog(
                PluginSchemaTable::new("counter")
                    .field("name", AdditionalField::new(AdditionalFieldType::String))
                    .field("value", AdditionalField::new(AdditionalFieldType::Number))
                    .field("active", AdditionalField::new(AdditionalFieldType::Boolean))
                    .field("when", AdditionalField::new(AdditionalFieldType::Date))
                    .field("metadata", AdditionalField::new(AdditionalFieldType::Json))
                    .field(
                        "tags",
                        AdditionalField::new(AdditionalFieldType::StringArray),
                    )
                    .field(
                        "note",
                        AdditionalField::new(AdditionalFieldType::String).optional(),
                    ),
                [62; 32],
            ),
            SqliteMigrationMode::Compile,
        )
        .await
        .unwrap();
    assert_eq!(empty.compiled_sql(), ";");
}

#[tokio::test]
async fn logical_plugin_rows_use_the_public_native_transaction() {
    let store = store().await;
    let updated = run_database_transaction(&store, |transaction| {
        Box::pin(async move {
            transaction
                .create_record("counter", record("native", "Native", 4))
                .await?;
            transaction
                .increment_record(
                    "counter",
                    &[equal("id", json!("native"))],
                    Map::from_iter([("value".into(), json!(3))]),
                    Map::from_iter([("note".into(), json!("committed"))]),
                )
                .await?
                .ok_or(AuthError::NotFound)
        })
    })
    .await
    .unwrap();
    assert_eq!(updated["value"], 7);
    assert_eq!(updated["note"], "committed");

    let error = run_database_transaction::<(), _>(&store, |transaction| {
        Box::pin(async move {
            transaction
                .update_record(
                    "counter",
                    &[equal("id", json!("native"))],
                    Map::from_iter([("value".into(), json!(99))]),
                )
                .await?;
            Err(AuthError::Storage("rollback".into()))
        })
    })
    .await
    .unwrap_err();
    assert!(matches!(error, AuthError::Storage(message) if message == "rollback"));
    assert_eq!(
        store
            .find_record(
                "counter",
                &[SqliteFilter::equal("id", json!("native"))],
                &[],
            )
            .await
            .unwrap()
            .unwrap()["value"],
        7
    );
}

fn equal(field: &str, value: Value) -> DashAdapterWhere {
    DashAdapterWhere {
        field: field.into(),
        value,
        operator: Default::default(),
        connector: None,
    }
}
