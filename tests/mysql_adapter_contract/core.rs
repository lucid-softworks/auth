use crate::support::pool;
use chrono::{Duration, Utc};
use lucid_auth::mysql::{MySqlAdapterConfig, MySqlStore};
use lucid_auth::{
    ApiKey, ApiKeyConfiguration, ApiKeyPlugin, ApiKeyStore, AuthConfig, AuthError, AuthService,
    AuthSession, AuthStore, AuthUser, DatabaseCreate, DatabaseCreateOperation,
    DatabaseIdGeneration, DatabaseIdInput, DatabaseIdPlan, DatabaseRecord, OAuthAccount,
    OAuthAccountStore, VerificationStore, VerificationValue, run_database_transaction,
};
use serde_json::Map;
use std::sync::Arc;

async fn store() -> MySqlStore {
    store_with(AuthConfig::new([91; 32]).unwrap()).await
}

async fn store_with(config: AuthConfig) -> MySqlStore {
    let store = MySqlStore::new(pool(1).await, MySqlAdapterConfig::default());
    let service = AuthService::new(Arc::new(store.clone()), config);
    let catalog = Arc::new(service.database_schema().clone());
    store.migrate(catalog).await.unwrap();
    store
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
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
        name: "MySQL User".into(),
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
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
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
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
async fn duplicate_user_email_is_classified_as_a_domain_conflict() {
    let store = store().await;
    let now = Utc::now();
    store
        .create_user_without_account(create("user", "user-1", user(now)))
        .await
        .unwrap();
    let error = store
        .create_user_without_account(create("user", "user-2", user(now)))
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::UserAlreadyExists));
}

#[tokio::test]
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
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
#[ignore = "requires MySQL in MYSQL_DATABASE_URL"]
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
