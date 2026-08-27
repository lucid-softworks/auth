#![cfg(feature = "sqlite")]

use chrono::{Duration, Timelike, Utc};
use lucid_auth::sqlite::{SqliteAdapterConfig, SqliteStore};
use lucid_auth::{
    AgentApprovalMethod, AgentApprovalRequest, AgentApprovalStatus, AgentAuthConfig,
    AgentAuthPlugin, AgentAuthStore, AgentCapabilityGrant, AgentGrantStatus, AgentHost,
    AgentHostRotationOutcome, AgentHostStatus, AgentIdentity, AgentMode, AgentRegistrationBundle,
    AgentRegistrationOutcome, AgentStatus, AgentStoreCreateOutcome, ApiKey, ApiKeyConfiguration,
    ApiKeyPlugin, ApiKeyStore, AuthConfig, AuthService, AuthSession, AuthStore, AuthUser,
    DatabaseCreate, DatabaseCreateOperation, DatabaseIdGeneration, DatabaseIdInput, DatabaseIdPlan,
    DatabaseIdValue, DatabaseRecord, JwtPlugin, OAuthAccount, OAuthAccountStore,
    OAuthProviderPlugin, OAuthProviderPluginConfig, OAuthProviderResource,
    OAuthProviderResourceStore, Organization, OrganizationDataStore, OrganizationPlugin,
    PreparedDatabaseId, VerificationStore, VerificationValue, run_database_transaction,
};
use serde_json::Map;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{str::FromStr, sync::Arc};

async fn store() -> SqliteStore {
    store_with(AuthConfig::new([91; 32]).unwrap()).await
}

#[tokio::test]
async fn oauth_provider_resource_rows_use_the_plugin_catalog() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = SqliteStore::new(pool, SqliteAdapterConfig::default());
    let mut config = AuthConfig::new([94; 32]).unwrap();
    config.add_plugin(JwtPlugin::default()).unwrap();
    config
        .add_plugin(OAuthProviderPlugin::new(
            OAuthProviderPluginConfig::new("/login", "/consent"),
            store.clone(),
        ))
        .unwrap();
    let service = AuthService::new(Arc::new(store.clone()), config);
    store
        .migrate(Arc::new(service.database_schema().clone()))
        .await
        .unwrap();
    let id = || {
        Ok(PreparedDatabaseId::Value(DatabaseIdValue::String(
            "resource-1".into(),
        )))
    };
    let resource = OAuthProviderResource {
        id: String::new(),
        identifier: "https://resource.example".into(),
        name: "Resource".into(),
        access_token_ttl: Some(900),
        refresh_token_ttl: None,
        signing_algorithm: None,
        signing_key_id: None,
        allowed_scopes: Some(vec!["read".into()]),
        custom_claims: Some(serde_json::json!({"aud": "resource"})),
        dpop_bound_access_tokens_required: false,
        disabled: false,
        created_at: Some(Utc::now()),
        updated_at: None,
        policy_version: 1,
        metadata: Some(serde_json::json!({"tier": "internal"})),
    };
    let stored = store
        .create_oauth_resource(&id, resource)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.id, "resource-1");
    assert_eq!(stored.allowed_scopes, Some(vec!["read".into()]));
    assert_eq!(
        store
            .find_oauth_resource("https://resource.example")
            .await
            .unwrap(),
        Some(stored)
    );
}

#[tokio::test]
async fn organization_metadata_uses_better_auth_string_storage() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = SqliteStore::new(pool, SqliteAdapterConfig::default());
    let mut config = AuthConfig::new([93; 32]).unwrap();
    config
        .add_plugin(OrganizationPlugin::new(Arc::new(store.clone())))
        .unwrap();
    let service = AuthService::new(Arc::new(store.clone()), config);
    store
        .migrate(Arc::new(service.database_schema().clone()))
        .await
        .unwrap();
    let now = Utc::now();
    let id = || {
        Ok(PreparedDatabaseId::Value(DatabaseIdValue::String(
            "organization-1".into(),
        )))
    };
    let organization = store
        .raw_insert_organization(
            Organization {
                id: String::new(),
                name: "SQLite Org".into(),
                slug: "sqlite-org".into(),
                logo: None,
                metadata: Some(serde_json::json!({"plan": "pro"})),
                created_at: now,
            },
            &id,
        )
        .await
        .unwrap();
    assert_eq!(
        organization.metadata,
        Some(serde_json::json!({"plan": "pro"}))
    );
    assert_eq!(
        store.find_organization_by_slug("sqlite-org").await.unwrap(),
        Some(organization)
    );
}

#[tokio::test]
async fn agent_auth_models_and_atomic_lifecycle_use_sqlite() {
    let store = agent_auth_store().await;
    let now = Utc::now();
    let now = now
        .with_nanosecond(now.timestamp_subsec_millis() * 1_000_000)
        .unwrap();
    let (host, agent, grant, approval) = agent_auth_records(now);
    let outcome = store
        .register_agent_bundle(AgentRegistrationBundle {
            host: Some(host.clone()),
            agent: agent.clone(),
            grants: vec![grant.clone()],
            approval: Some(approval.clone()),
        })
        .await
        .unwrap();
    assert!(matches!(outcome, AgentRegistrationOutcome::Registered(_)));
    assert_agent_auth_records(&store, &host, &agent, &grant, &approval).await;
    assert!(matches!(
        store
            .create_host(AgentHost {
                id: "agent-host-duplicate".into(),
                ..host
            })
            .await
            .unwrap(),
        AgentStoreCreateOutcome::UniqueConflict
    ));
    assert!(matches!(
        store
            .rotate_host_key(
                &host.id,
                "agent-host-2",
                "rotated-host-public-key".into(),
                Some("rotated-host-kid".into()),
                now + Duration::seconds(1),
            )
            .await
            .unwrap(),
        AgentHostRotationOutcome::Rotated(_)
    ));
    assert_eq!(
        store.find_agent(&agent.id).await.unwrap().unwrap().host_id,
        "agent-host-2"
    );
    assert_eq!(
        store
            .find_approval(&approval.id)
            .await
            .unwrap()
            .unwrap()
            .host_id
            .as_deref(),
        Some("agent-host-2")
    );
    let revoked = store
        .revoke_agent_cascade(&agent.id, now + Duration::seconds(2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revoked.grants_revoked, 1);
    assert_eq!(
        store.find_agent(&agent.id).await.unwrap().unwrap().status,
        AgentStatus::Revoked
    );
}

async fn agent_auth_store() -> SqliteStore {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::from_str("sqlite::memory:")
                .unwrap()
                .foreign_keys(true),
        )
        .await
        .unwrap();
    let store = SqliteStore::new(pool, SqliteAdapterConfig::default());
    let mut config = AuthConfig::new([98; 32]).unwrap();
    config
        .add_plugin(AgentAuthPlugin::new(AgentAuthConfig::default(), store.clone()).unwrap())
        .unwrap();
    let service = AuthService::new(Arc::new(store.clone()), config);
    store
        .migrate(Arc::new(service.database_schema().clone()))
        .await
        .unwrap();
    store
}

fn agent_auth_records(
    now: chrono::DateTime<Utc>,
) -> (
    AgentHost,
    AgentIdentity,
    AgentCapabilityGrant,
    AgentApprovalRequest,
) {
    let host = agent_host(now);
    let agent = agent_identity(now, &host.id);
    let grant = agent_grant(now, &agent.id);
    let approval = agent_approval(now, &host.id, &agent.id);
    (host, agent, grant, approval)
}

fn agent_host(now: chrono::DateTime<Utc>) -> AgentHost {
    AgentHost {
        id: "agent-host-1".into(),
        name: Some("Host".into()),
        user_id: None,
        default_capabilities: vec!["files.read".into()],
        public_key: Some("host-public-key".into()),
        kid: Some("host-kid".into()),
        jwks_url: None,
        enrollment_token_hash: None,
        enrollment_token_expires_at: None,
        status: AgentHostStatus::Active,
        activated_at: Some(now),
        expires_at: None,
        last_used_at: None,
        created_at: now,
        updated_at: now,
    }
}

fn agent_identity(now: chrono::DateTime<Utc>, host_id: &str) -> AgentIdentity {
    AgentIdentity {
        id: "agent-1".into(),
        name: "SQLite Agent".into(),
        user_id: None,
        host_id: host_id.into(),
        status: AgentStatus::Active,
        mode: AgentMode::Autonomous,
        public_key: "agent-public-key".into(),
        kid: Some("agent-kid".into()),
        jwks_url: None,
        last_used_at: None,
        activated_at: Some(now),
        expires_at: None,
        metadata: Some(serde_json::Map::from_iter([(
            "runtime".into(),
            serde_json::json!("sqlite"),
        )])),
        created_at: now,
        updated_at: now,
    }
}

fn agent_grant(now: chrono::DateTime<Utc>, agent_id: &str) -> AgentCapabilityGrant {
    AgentCapabilityGrant {
        id: "agent-grant-1".into(),
        agent_id: agent_id.into(),
        capability: "files.read".into(),
        constraints: None,
        denied_by: None,
        granted_by: None,
        expires_at: None,
        status: AgentGrantStatus::Active,
        reason: None,
        created_at: now,
        updated_at: now,
    }
}

fn agent_approval(
    now: chrono::DateTime<Utc>,
    host_id: &str,
    agent_id: &str,
) -> AgentApprovalRequest {
    AgentApprovalRequest {
        id: "agent-approval-1".into(),
        method: AgentApprovalMethod::DeviceAuthorization,
        agent_id: Some(agent_id.into()),
        host_id: Some(host_id.into()),
        user_id: None,
        capabilities: Some("files.read".into()),
        status: AgentApprovalStatus::Pending,
        user_code_hash: Some("agent-code-hash".into()),
        login_hint: None,
        binding_message: None,
        client_notification_token: None,
        client_notification_endpoint: None,
        delivery_mode: None,
        interval: 5.0,
        last_polled_at: None,
        expires_at: now + Duration::minutes(5),
        created_at: now,
        updated_at: now,
    }
}

async fn assert_agent_auth_records(
    store: &SqliteStore,
    host: &AgentHost,
    agent: &AgentIdentity,
    grant: &AgentCapabilityGrant,
    approval: &AgentApprovalRequest,
) {
    assert_eq!(
        store.find_host_by_kid("host-kid").await.unwrap(),
        Some(host.clone())
    );
    assert_eq!(
        store.find_agent_by_kid("agent-kid").await.unwrap(),
        Some(agent.clone())
    );
    assert_eq!(
        store.find_grant_by_id(&grant.id).await.unwrap(),
        Some(grant.clone())
    );
    assert_eq!(
        store
            .find_approval_by_user_code_hash("agent-code-hash")
            .await
            .unwrap(),
        Some(approval.clone())
    );
}

async fn store_with(config: AuthConfig) -> SqliteStore {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = SqliteStore::new(pool, SqliteAdapterConfig::default());
    let service = AuthService::new(Arc::new(store.clone()), config);
    let catalog = Arc::new(service.database_schema().clone());
    store.migrate(catalog).await.unwrap();
    store
}

#[tokio::test]
async fn api_key_hash_uses_the_pinned_key_column_and_round_trips() {
    let mut config = AuthConfig::new([92; 32]).unwrap();
    config
        .add_plugin(ApiKeyPlugin::new(ApiKeyConfiguration::default()))
        .unwrap();
    let store = store_with(config).await;
    let now = Utc::now();
    let key = ApiKey {
        id: String::new(),
        config_id: "default".into(),
        name: Some("test".into()),
        start: Some("start".into()),
        prefix: None,
        key_hash: "private-hash".into(),
        reference_id: "user-1".into(),
        refill_interval: None,
        refill_amount: None,
        last_refill_at: None,
        enabled: true,
        rate_limit_enabled: false,
        rate_limit_time_window: None,
        rate_limit_max: None,
        request_count: 0,
        remaining: None,
        last_request: None,
        expires_at: None,
        permissions: None,
        metadata: None,
        created_at: now,
        updated_at: now,
    };
    let stored = store
        .create_api_key(create("apikey", "key-1", key))
        .await
        .unwrap();
    assert_eq!(stored.key_hash, "private-hash");
    assert_eq!(
        store
            .find_api_key_by_hash("private-hash")
            .await
            .unwrap()
            .unwrap()
            .id,
        "key-1"
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

fn user(now: chrono::DateTime<Utc>) -> AuthUser {
    AuthUser {
        id: String::new(),
        username: Some("not-installed".into()),
        display_username: Some("Not Installed".into()),
        name: "SQLite User".into(),
        email: "USER@EXAMPLE.COM".into(),
        email_verified: true,
        image: None,
        additional_fields: Map::new(),
        role: "admin".into(),
        is_anonymous: true,
        banned: true,
        ban_reason: Some("not-installed".into()),
        ban_expires: Some(now),
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn core_rows_use_bound_schema_and_transient_plugin_defaults() {
    let store = store().await;
    let now = Utc::now();
    let stored = store
        .create_user_without_account(create("user", "user-1", user(now)))
        .await
        .unwrap();
    assert_eq!(stored.id, "user-1");
    assert_eq!(stored.email, "user@example.com");
    assert_eq!(stored.username, None);
    assert_eq!(stored.role, "user");
    assert!(!stored.is_anonymous && !stored.banned);

    let session = AuthSession {
        id: String::new(),
        user_id: stored.id.clone(),
        token: "token-1".into(),
        actor_user_id: Some("not-installed".into()),
        authentication_method: None,
        expires_at: now + Duration::hours(1),
        created_at: now,
        updated_at: now,
        ip_address: Some("127.0.0.1".into()),
        user_agent: None,
        additional_fields: Map::new(),
    };
    let session = store
        .create_session(create("session", "session-1", session))
        .await
        .unwrap();
    assert_eq!(session.actor_user_id, None);
    assert_eq!(
        store.find_session("token-1").await.unwrap().unwrap().1,
        stored
    );
}

#[tokio::test]
async fn hook_transactions_expose_staged_rows_and_roll_back_once() {
    let store = store().await;
    let now = Utc::now();
    let reentrant_store = store.clone();
    let result = run_database_transaction::<(), _>(&store, move |transaction| {
        Box::pin(async move {
            let stored = transaction
                .create(DatabaseCreateOperation::User(create(
                    "user",
                    "transaction-user",
                    user(now),
                )))
                .await?;
            assert!(matches!(stored, DatabaseRecord::User(_)));
            assert_eq!(
                reentrant_store
                    .find_user_by_id("transaction-user")
                    .await?
                    .unwrap()
                    .email,
                "user@example.com"
            );
            Err(lucid_auth::AuthError::Storage("force rollback".into()))
        })
    })
    .await;
    assert!(matches!(result, Err(lucid_auth::AuthError::Storage(_))));
    assert!(
        store
            .find_user_by_id("transaction-user")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn secret_account_fields_and_one_time_values_round_trip() {
    let store = store().await;
    let now = Utc::now();
    let user = store
        .create_user_without_account(create("user", "user-1", user(now)))
        .await
        .unwrap();
    let account = OAuthAccount {
        id: String::new(),
        user_id: user.id,
        issuer: "https://issuer.example".into(),
        account_id: "subject".into(),
        provider_id: "provider".into(),
        access_token: Some("access-secret".into()),
        refresh_token: Some("refresh-secret".into()),
        id_token: Some("id-secret".into()),
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: Some("openid".into()),
        password: None,
        additional_fields: Map::new(),
        created_at: now,
        updated_at: now,
    };
    let account = store
        .link_oauth_account(create("account", "account-1", account))
        .await
        .unwrap();
    assert_eq!(account.access_token.as_deref(), Some("access-secret"));
    assert_eq!(account.refresh_token.as_deref(), Some("refresh-secret"));
    assert_eq!(account.id_token.as_deref(), Some("id-secret"));

    let verification = VerificationValue {
        id: String::new(),
        identifier: "challenge".into(),
        value: "one-time".into(),
        expires_at: now + Duration::minutes(5),
        created_at: now,
        updated_at: now,
    };
    store
        .create_verification(create("verification", "verification-1", verification))
        .await
        .unwrap();
    assert!(
        store
            .consume_verification("challenge")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .consume_verification("challenge")
            .await
            .unwrap()
            .is_none()
    );
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
    let path = std::env::temp_dir().join(format!(
        "lucid-auth-sqlite-contract-{}.db",
        uuid::Uuid::new_v4()
    ));
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .unwrap();
    shared_storage_contract(pool.clone()).await;
    pool.close().await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn separate_connections_atomically_consume_and_increment() {
    let path = std::env::temp_dir().join(format!(
        "lucid-auth-sqlite-concurrency-{}.db",
        uuid::Uuid::new_v4()
    ));
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
        .unwrap();
    let mut config = AuthConfig::new([96; 32]).unwrap();
    config
        .add_plugin(ApiKeyPlugin::new(ApiKeyConfiguration::default()))
        .unwrap();
    let store = SqliteStore::new(pool.clone(), SqliteAdapterConfig::default());
    let service = AuthService::new(Arc::new(store.clone()), config);
    store
        .migrate(Arc::new(service.database_schema().clone()))
        .await
        .unwrap();

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

    store
        .create_api_key(create(
            "apikey",
            "counter-key",
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
            },
        ))
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
                    &[lucid_auth::sqlite::SqliteFilter::equal(
                        "id",
                        serde_json::json!("counter-key"),
                    )],
                    serde_json::Map::from_iter([("requestCount".into(), serde_json::json!(1))]),
                    serde_json::Map::new(),
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

    pool.close().await;
    std::fs::remove_file(path).unwrap();
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
    let normalized = session_sql.to_ascii_lowercase();
    assert!(normalized.contains("references \"user\" (\"id\") on delete cascade"));

    let now = Utc::now();
    let error = store
        .insert_record(
            "session",
            serde_json::Map::from_iter([
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
