use crate::support::pool;
use chrono::{Duration, Utc};
use lucid_auth::mysql::{MySqlAdapterConfig, MySqlFilter, MySqlStore};
use lucid_auth::{
    ApiKey, ApiKeyConfiguration, ApiKeyPlugin, ApiKeyStore, AuthConfig, AuthService, AuthStore,
    AuthUser, DatabaseCreate, DatabaseIdGeneration, DatabaseIdInput, DatabaseIdPlan,
    VerificationStore, VerificationValue,
};
use serde_json::Map;
use std::sync::Arc;

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
        name: "MySQL User".into(),
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

async fn shared_storage_contract(pool: sqlx::MySqlPool) {
    let mut config = AuthConfig::new([95; 32]).unwrap();
    config
        .add_plugin(ApiKeyPlugin::new(ApiKeyConfiguration::default()))
        .unwrap();
    let store = MySqlStore::new(pool, MySqlAdapterConfig::default());
    let service = AuthService::new(Arc::new(store.clone()), config);
    let catalog = Arc::new(service.database_schema().clone());
    store.migrate(catalog.clone()).await.unwrap();
    assert_eq!(
        store
            .migration_plan(catalog, lucid_auth::mysql::MySqlMigrationMode::Execute)
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
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn shared_storage_contract_runs_on_one_connection() {
    shared_storage_contract(pool(1).await).await;
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn shared_storage_contract_runs_on_a_pool() {
    shared_storage_contract(pool(4).await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn separate_connections_atomically_consume_and_increment() {
    let store = concurrency_store(pool(32).await).await;
    assert_single_consumer(&store).await;
    assert_atomic_increments(&store).await;
}

async fn concurrency_store(pool: sqlx::MySqlPool) -> MySqlStore {
    let mut config = AuthConfig::new([96; 32]).unwrap();
    config
        .add_plugin(ApiKeyPlugin::new(ApiKeyConfiguration::default()))
        .unwrap();
    let store = MySqlStore::new(pool, MySqlAdapterConfig::default());
    let service = AuthService::new(Arc::new(store.clone()), config);
    store
        .migrate(Arc::new(service.database_schema().clone()))
        .await
        .unwrap();
    store
}

async fn assert_single_consumer(store: &MySqlStore) {
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

async fn assert_atomic_increments(store: &MySqlStore) {
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
                    &[MySqlFilter::equal("id", serde_json::json!("counter-key"))],
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
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn readiness_preserves_utc_and_foreign_keys() {
    let pool = pool(4).await;
    let before: String = sqlx::query_scalar("select @@session.time_zone")
        .fetch_one(&pool)
        .await
        .unwrap();
    let store = MySqlStore::new(pool.clone(), MySqlAdapterConfig::default());
    store.ready().await.unwrap();
    let service = AuthService::new(Arc::new(store.clone()), AuthConfig::new([97; 32]).unwrap());
    store
        .migrate(Arc::new(service.database_schema().clone()))
        .await
        .unwrap();
    let after: String = sqlx::query_scalar("select @@session.time_zone")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, "+00:00");
    assert_eq!(after, before);
    assert_foreign_key_rejection(&store).await;
}

async fn assert_foreign_key_rejection(store: &MySqlStore) {
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
    assert!(
        error
            .to_string()
            .to_ascii_lowercase()
            .contains("foreign key")
    );
}
