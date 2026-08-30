use chrono::{Duration, Utc};
use lucid_auth::sqlite::{SqliteAdapterConfig, SqliteFilter, SqliteStore};
use lucid_auth::{
    ApiKey, ApiKeyConfiguration, ApiKeyPlugin, ApiKeyStore, AuthConfig, AuthService, AuthStore,
    AuthUser, DatabaseCreate, DatabaseIdGeneration, DatabaseIdInput, DatabaseIdPlan,
    VerificationStore, VerificationValue,
};
use serde_json::Map;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{str::FromStr, sync::Arc};

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

fn user(now: chrono::DateTime<Utc>) -> AuthUser {
    AuthUser {
        id: String::new(),
        username: None,
        display_username: None,
        name: "SQLite User".into(),
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

async fn shared_storage_contract(pool: sqlx::SqlitePool) {
    let mut config = AuthConfig::new([95; 32]).unwrap();
    config
        .add_plugin(ApiKeyPlugin::new(ApiKeyConfiguration::default()))
        .unwrap();
    let store = SqliteStore::new(pool, SqliteAdapterConfig::default());
    let service = AuthService::new(Arc::new(store.clone()), config);
    let catalog = Arc::new(service.database_schema().clone());
    store.migrate(catalog.clone()).await.unwrap();
    assert_eq!(
        store
            .migration_plan(catalog, lucid_auth::sqlite::SqliteMigrationMode::Execute)
            .await
            .unwrap()
            .compiled_sql(),
        ";"
    );

    let now = Utc::now();
    let user = store
        .create_user_without_account(create("user", "shared-user", user(now)))
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

    let mut transaction = store.begin().await.unwrap();
    transaction
        .insert_record(
            "verification",
            serde_json::Map::from_iter([
                ("id".into(), serde_json::json!("rolled-back")),
                ("identifier".into(), serde_json::json!("rollback")),
                ("value".into(), serde_json::json!("secret")),
                (
                    "expiresAt".into(),
                    serde_json::json!(now + Duration::minutes(5)),
                ),
                ("createdAt".into(), serde_json::json!(now)),
                ("updatedAt".into(), serde_json::json!(now)),
            ]),
        )
        .await
        .unwrap();
    transaction.rollback().await.unwrap();
    assert!(store.find_verification("rollback").await.unwrap().is_none());
}

#[tokio::test]
async fn shared_storage_contract_runs_on_one_connection_memory() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    shared_storage_contract(pool).await;
}

#[tokio::test]
async fn shared_storage_contract_runs_on_a_temporary_file() {
    let path = temporary_database("contract");
    let pool = file_pool(&path, 4).await;
    shared_storage_contract(pool.clone()).await;
    pool.close().await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn separate_connections_atomically_consume_and_increment() {
    let path = temporary_database("concurrency");
    let pool = file_pool(&path, 8).await;
    let store = concurrency_store(pool.clone()).await;
    assert_single_consumer(&store).await;
    assert_atomic_increments(&store).await;
    pool.close().await;
    std::fs::remove_file(path).unwrap();
}

async fn concurrency_store(pool: sqlx::SqlitePool) -> SqliteStore {
    let mut config = AuthConfig::new([96; 32]).unwrap();
    config
        .add_plugin(ApiKeyPlugin::new(ApiKeyConfiguration::default()))
        .unwrap();
    let store = SqliteStore::new(pool, SqliteAdapterConfig::default());
    let service = AuthService::new(Arc::new(store.clone()), config);
    store
        .migrate(Arc::new(service.database_schema().clone()))
        .await
        .unwrap();
    store
}

async fn assert_single_consumer(store: &SqliteStore) {
    let now = Utc::now();
    store
        .create_verification(create(
            "verification",
            "consume-once",
            VerificationValue {
                id: String::new(),
                identifier: "concurrent".into(),
                value: "secret".into(),
                expires_at: now + Duration::minutes(5),
                created_at: now,
                updated_at: now,
            },
        ))
        .await
        .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(16));
    let mut consumers = Vec::new();
    for _ in 0..16 {
        let store = store.clone();
        let barrier = barrier.clone();
        consumers.push(tokio::spawn(async move {
            barrier.wait().await;
            store.consume_verification("concurrent").await
        }));
    }
    let mut consumed = 0;
    for consumer in consumers {
        consumed += usize::from(consumer.await.unwrap().unwrap().is_some());
    }
    assert_eq!(consumed, 1);
}

async fn assert_atomic_increments(store: &SqliteStore) {
    let now = Utc::now();
    store
        .create_api_key(create("apikey", "counter-key", counter_key(now)))
        .await
        .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(32));
    let mut increments = Vec::new();
    for _ in 0..32 {
        let store = store.clone();
        let barrier = barrier.clone();
        increments.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .increment_record(
                    "apikey",
                    &[SqliteFilter::equal("id", serde_json::json!("counter-key"))],
                    Map::from_iter([("requestCount".into(), serde_json::json!(1))]),
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
            .find_api_key("counter-key")
            .await
            .unwrap()
            .unwrap()
            .request_count,
        32
    );
}

fn counter_key(now: chrono::DateTime<Utc>) -> ApiKey {
    ApiKey {
        id: String::new(),
        config_id: "default".into(),
        name: None,
        start: None,
        prefix: None,
        key_hash: "counter-hash".into(),
        reference_id: "counter-user".into(),
        refill_interval: None,
        refill_amount: None,
        last_refill_at: None,
        enabled: true,
        rate_limit_enabled: true,
        rate_limit_time_window: Some(60_000),
        rate_limit_max: Some(100),
        request_count: 0,
        remaining: None,
        last_request: Some(now),
        expires_at: None,
        permissions: None,
        metadata: None,
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn caller_controls_foreign_keys_and_other_connection_pragmas() {
    let options = SqliteConnectOptions::from_str("sqlite::memory:")
        .unwrap()
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let before = pragma_snapshot(&pool).await;
    let store = SqliteStore::new(pool.clone(), SqliteAdapterConfig::default());
    let service = AuthService::new(Arc::new(store.clone()), AuthConfig::new([97; 32]).unwrap());
    store
        .migrate(Arc::new(service.database_schema().clone()))
        .await
        .unwrap();
    assert_eq!(pragma_snapshot(&pool).await, before);
    assert_eq!(before.0, 1);

    let session_sql: String = sqlx::query_scalar(
        "select sql from sqlite_master where type = 'table' and name = 'session'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        session_sql
            .to_ascii_lowercase()
            .contains("references \"user\" (\"id\") on delete cascade")
    );
    assert_foreign_key_rejection(&store).await;
}

async fn assert_foreign_key_rejection(store: &SqliteStore) {
    let now = Utc::now();
    let error = store
        .insert_record(
            "session",
            Map::from_iter([
                ("id".into(), serde_json::json!("orphan-session")),
                ("userId".into(), serde_json::json!("missing-user")),
                ("token".into(), serde_json::json!("orphan-token")),
                (
                    "expiresAt".into(),
                    serde_json::json!(now + Duration::minutes(5)),
                ),
                ("createdAt".into(), serde_json::json!(now)),
                ("updatedAt".into(), serde_json::json!(now)),
            ]),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("FOREIGN KEY constraint failed"));
}

async fn pragma_snapshot(pool: &sqlx::SqlitePool) -> (i64, String, i64, i64) {
    (
        sqlx::query_scalar("pragma foreign_keys")
            .fetch_one(pool)
            .await
            .unwrap(),
        sqlx::query_scalar("pragma journal_mode")
            .fetch_one(pool)
            .await
            .unwrap(),
        sqlx::query_scalar("pragma synchronous")
            .fetch_one(pool)
            .await
            .unwrap(),
        sqlx::query_scalar("pragma busy_timeout")
            .fetch_one(pool)
            .await
            .unwrap(),
    )
}

fn temporary_database(kind: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "lucid-auth-sqlite-{kind}-{}.db",
        uuid::Uuid::new_v4()
    ))
}

async fn file_pool(path: &std::path::Path, connections: u32) -> sqlx::SqlitePool {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true);
    SqlitePoolOptions::new()
        .max_connections(connections)
        .connect_with(options)
        .await
        .unwrap()
}
