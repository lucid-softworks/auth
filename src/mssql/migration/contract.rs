use crate::{
    AdditionalField, AdditionalFieldReference, AdditionalFieldType, ApiKey, ApiKeyConfiguration,
    ApiKeyPlugin, ApiKeyStore, AuthConfig, AuthSchemaCatalog, AuthService, AuthStore, AuthUser,
    DatabaseCreate, DatabaseIdGeneration, DatabaseIdInput, DatabaseIdPlan, PluginSchemaTable,
    run_database_transaction,
    mssql::{
        MssqlAdapterConfig, MssqlComparisonMode, MssqlFilter, MssqlFilterConnector,
        MssqlFilterOperator, MssqlFindOptions, MssqlMigrationMode, MssqlSort,
        MssqlSortDirection, MssqlStore,
    },
};

mod joins;
mod fixture;
use fixture::record;
use serde_json::{Map, json};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

static DATABASE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn counter() -> PluginSchemaTable {
    PluginSchemaTable::new("counter")
        .model_name("auth_counter")
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
        .field(
            "groupId",
            AdditionalField::new(AdditionalFieldType::String)
                .field_name("group_id")
                .optional()
                .references(AdditionalFieldReference {
                    model: "group".into(),
                    field: "id".into(),
                    on_delete: None,
                }),
        )
}

fn group() -> PluginSchemaTable {
    PluginSchemaTable::new("group")
        .model_name("auth_group")
        .field("name", AdditionalField::new(AdditionalFieldType::String))
}

fn catalog(serial: bool) -> Arc<AuthSchemaCatalog> {
    let mut config = AuthConfig::new([64; 32]).unwrap();
    if serial {
        config.database_id_generation = crate::DatabaseIdGeneration::Serial;
    }
    Arc::new(AuthSchemaCatalog::build(&config, [group(), counter()]).unwrap())
}

async fn store(serial: bool) -> MssqlStore {
    let store = raw_store().await;
    store.migrate(catalog(serial)).await.unwrap();
    store
}

async fn raw_store() -> MssqlStore {
    raw_store_with(MssqlAdapterConfig::default()).await
}

async fn raw_store_with(adapter_config: MssqlAdapterConfig) -> MssqlStore {
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
    let store = MssqlStore::connect_with(config, 16, adapter_config)
        .await
        .unwrap();
    store
}

#[tokio::test]
#[ignore = "requires SQL Server in MSSQL_DATABASE_URL"]
async fn migrates_and_matches_runtime_query_semantics() {
    let store = store(false).await;
    let inserted = fixture::seed(&store).await;
    assert_eq!(inserted["when"], json!("2026-08-31T12:34:56.123Z"));
    assert_eq!(inserted["metadata"], json!({"nested": true}));
    assert_eq!(inserted["tags"], json!(["one", "two"]));
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
                joins: Vec::new(),
            },
        )
        .await
        .unwrap();
    assert_eq!(page[0]["name"], json!("Beta"));

    joins::assert_joins(&store).await;

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

#[tokio::test]
#[ignore = "requires SQL Server in MSSQL_DATABASE_URL"]
async fn runs_core_and_plugin_typed_stores() {
    let mut config = AuthConfig::new([65; 32]).unwrap();
    config
        .add_plugin(ApiKeyPlugin::new(ApiKeyConfiguration::default()))
        .unwrap();
    let store = raw_store().await;
    let service = AuthService::new(Arc::new(store.clone()), config);
    store
        .migrate(Arc::new(service.database_schema().clone()))
        .await
        .unwrap();

    let now = chrono::Utc::now();
    let user = store
        .create_user_without_account(create("user", "typed-user", typed_user(now)))
        .await
        .unwrap();
    assert_eq!(
        store
            .find_user_by_email("USER@example.com")
            .await
            .unwrap()
            .unwrap()
            .id,
        user.id
    );

    let key = store
        .create_api_key(create("apikey", "typed-key", typed_key(user.id, now)))
        .await
        .unwrap();
    assert_eq!(
        store.find_api_key(&key.id).await.unwrap().unwrap().key_hash,
        "typed-hash"
    );
}

fn create<T>(model: &str, id: &str, record: T) -> DatabaseCreate<T> {
    DatabaseCreate::new(
        record,
        DatabaseIdPlan::new(
            DatabaseIdGeneration::Default,
            model,
            DatabaseIdInput::String(id.into()),
            true,
        ),
    )
}

fn typed_user(now: chrono::DateTime<chrono::Utc>) -> AuthUser {
    AuthUser {
        id: String::new(),
        username: None,
        display_username: None,
        name: "MSSQL User".into(),
        email: "USER@EXAMPLE.COM".into(),
        email_verified: true,
        image: None,
        additional_fields: Map::new(),
        role: "user".into(),
        is_anonymous: false,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        created_at: now,
        updated_at: now,
    }
}

fn typed_key(reference_id: String, now: chrono::DateTime<chrono::Utc>) -> ApiKey {
    ApiKey {
        id: String::new(),
        config_id: "default".into(),
        name: None,
        start: None,
        prefix: None,
        key_hash: "typed-hash".into(),
        reference_id,
        refill_interval: None,
        refill_amount: None,
        last_refill_at: None,
        enabled: true,
        rate_limit_enabled: true,
        rate_limit_time_window: Some(60_000),
        rate_limit_max: Some(100),
        request_count: 0,
        remaining: None,
        last_request: None,
        expires_at: None,
        created_at: now,
        updated_at: now,
        metadata: None,
        permissions: None,
    }
}

#[tokio::test]
#[ignore = "requires SQL Server in MSSQL_DATABASE_URL"]
async fn wrapper_transaction_option_controls_rollback() {
    for (transaction, persists) in [(false, true), (true, false)] {
        let store = raw_store_with(MssqlAdapterConfig {
            transaction,
            ..MssqlAdapterConfig::default()
        })
        .await;
        store.migrate(catalog(false)).await.unwrap();
        let result = run_database_transaction::<(), _>(&store, move |database| {
            Box::pin(async move {
                database
                    .create_record("counter", record(Some("rollback"), "Rollback", 1))
                    .await?;
                Err(crate::AuthError::Storage("forced failure".into()))
            })
        })
        .await;
        assert!(result.is_err());
        assert_eq!(
            store
                .find_record(
                    "counter",
                    &[MssqlFilter::equal("id", json!("rollback"))],
                    &[],
                )
                .await
                .unwrap()
                .is_some(),
            persists,
            "transaction={transaction}",
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SQL Server in MSSQL_DATABASE_URL"]
async fn concurrent_consume_and_increment_remain_atomic() {
    let store = store(false).await;
    store
        .insert_record("counter", record(Some("counter"), "Concurrent", 0))
        .await
        .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(24));
    let mut increments = Vec::new();
    for _ in 0..24 {
        let store = store.clone();
        let barrier = barrier.clone();
        increments.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .increment_record(
                    "counter",
                    &[MssqlFilter::equal("id", json!("counter"))],
                    Map::from_iter([("value".into(), json!(1))]),
                    Map::new(),
                )
                .await
        }));
    }
    for increment in increments {
        assert!(increment.await.unwrap().unwrap().is_some());
    }
    assert_eq!(
        store
            .find_record(
                "counter",
                &[MssqlFilter::equal("id", json!("counter"))],
                &[],
            )
            .await
            .unwrap()
            .unwrap()["value"],
        json!(24)
    );

    store
        .insert_record("counter", record(Some("consume"), "Consume", 1))
        .await
        .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(16));
    let mut consumers = Vec::new();
    for _ in 0..16 {
        let store = store.clone();
        let barrier = barrier.clone();
        consumers.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .consume_record(
                    "counter",
                    &[MssqlFilter::equal("id", json!("consume"))],
                )
                .await
        }));
    }
    let mut consumed = 0;
    for consumer in consumers {
        consumed += usize::from(consumer.await.unwrap().unwrap().is_some());
    }
    assert_eq!(consumed, 1);
}
