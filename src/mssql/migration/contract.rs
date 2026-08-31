use crate::{
    AdditionalField, AdditionalFieldType, AuthConfig, AuthSchemaCatalog, PluginSchemaTable,
    mssql::{
        MssqlAdapterConfig, MssqlComparisonMode, MssqlFilter, MssqlFilterConnector,
        MssqlFilterOperator, MssqlFindOptions, MssqlMigrationMode, MssqlSort,
        MssqlSortDirection, MssqlStore,
    },
};
use serde_json::{Map, Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

static DATABASE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

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

fn catalog(serial: bool) -> Arc<AuthSchemaCatalog> {
    let mut config = AuthConfig::new([64; 32]).unwrap();
    if serial {
        config.database_id_generation = crate::DatabaseIdGeneration::Serial;
    }
    Arc::new(AuthSchemaCatalog::build(&config, [counter()]).unwrap())
}

async fn store(serial: bool) -> MssqlStore {
    let connection_string = std::env::var("MSSQL_DATABASE_URL").expect(
        "MSSQL_DATABASE_URL is required for ignored MSSQL contracts",
    );
    let admin = MssqlStore::connect(&connection_string, MssqlAdapterConfig::default())
        .await
        .unwrap();
    let database = format!(
        "lucid_auth_{}_{}",
        std::process::id(),
        DATABASE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let mut connection = admin.pool().get().await.unwrap();
    connection
        .simple_query(format!("create database [{database}]"))
        .await
        .unwrap()
        .into_results()
        .await
        .unwrap();
    drop(connection);
    let mut config = tiberius::Config::from_ado_string(&connection_string).unwrap();
    config.database(&database);
    let store = MssqlStore::connect_with(config, 16, MssqlAdapterConfig::default())
        .await
        .unwrap();
    store.migrate(catalog(serial)).await.unwrap();
    store
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

#[tokio::test]
#[ignore = "requires SQL Server in MSSQL_DATABASE_URL"]
async fn migrates_and_matches_runtime_query_semantics() {
    let store = store(false).await;
    let inserted = store
        .insert_record("counter", record(Some("one"), "Alpha", 4))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inserted["when"], json!("2026-08-31T12:34:56.123Z"));
    assert_eq!(inserted["metadata"], json!({"nested": true}));
    assert_eq!(inserted["tags"], json!(["one", "two"]));

    for (id, name, value) in [("two", "Beta", 7), ("three", "Alpine", 9)] {
        store
            .insert_record("counter", record(Some(id), name, value))
            .await
            .unwrap();
    }
    let insensitive = MssqlFilter {
        field: "name".into(),
        value: json!("ALP"),
        operator: MssqlFilterOperator::Contains,
        connector: MssqlFilterConnector::And,
        mode: MssqlComparisonMode::Insensitive,
    };
    assert_eq!(store.count_records("counter", &[insensitive]).await.unwrap(), 2);
    let page = store
        .find_records(
            "counter",
            &[],
            &MssqlFindOptions {
                select: vec!["name".into(), "value".into()],
                sort: Some(MssqlSort {
                    field: "value".into(),
                    direction: MssqlSortDirection::Descending,
                }),
                limit: Some(1),
                offset: Some(1),
            },
        )
        .await
        .unwrap();
    assert_eq!(page[0]["name"], json!("Beta"));

    let id = [MssqlFilter::equal("id", json!("one"))];
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
    assert_eq!(
        store
            .migration_plan(catalog(false), MssqlMigrationMode::Compile)
            .await
            .unwrap()
            .compiled_sql(),
        ";"
    );
}

#[tokio::test]
#[ignore = "requires SQL Server in MSSQL_DATABASE_URL"]
async fn returns_serial_identity_ids() {
    let store = store(true).await;
    let inserted = store
        .insert_record("counter", record(None, "Serial", 1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inserted["id"], json!("1"));
}
