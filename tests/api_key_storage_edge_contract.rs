use async_trait::async_trait;
use lucid_auth::{
    ApiKeyConfiguration, ApiKeyError, ApiKeyGenerator, ApiKeyRateLimitConfig, ApiKeySortDirection,
    ApiKeyStorage, ApiKeyStore, AuthConfig, AuthError, AuthService, MemoryStore, NewApiKey,
    NewPasswordUser, SessionWithUser, UsernamePlugin,
};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn secondary_reads_are_empty_when_no_storage_is_configured() {
    let (_, service, actor) = fixture().await;
    let config = ApiKeyConfiguration {
        storage: ApiKeyStorage::SecondaryStorage,
        ..ApiKeyConfiguration::default()
    };

    assert!(
        service
            .list_api_keys(&actor, &config, None, None, ApiKeySortDirection::Ascending)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        service.get_api_key(&actor, &config, "missing").await,
        Err(AuthError::ApiKey(ApiKeyError::NotFound))
    ));
    assert!(matches!(
        service
            .verify_api_key("missing", &[config], None, None)
            .await,
        Err(AuthError::ApiKey(ApiKeyError::Invalid))
    ));
}

#[tokio::test]
async fn fallback_reads_database_without_storage_but_cache_writes_still_require_it() {
    let (_, service, actor) = fixture().await;
    let database = database_config("FallbackWithoutStorageKey");
    let issued = issue(&service, &actor, &database, None).await;
    let fallback = ApiKeyConfiguration {
        storage: ApiKeyStorage::SecondaryStorage,
        fallback_to_database: true,
        ..database.clone()
    };

    let found = service
        .get_api_key(&actor, &fallback, &issued.api_key.id)
        .await
        .unwrap();
    assert_eq!(found.id, issued.api_key.id);
    assert!(matches!(
        service
            .verify_api_key(&issued.key, &[fallback], None, None)
            .await,
        Err(AuthError::Storage(message)) if message.contains("Secondary storage is required")
    ));
}

#[tokio::test]
async fn database_reads_migrate_double_stringified_metadata() {
    let (store, service, actor) = fixture().await;
    let config = ApiKeyConfiguration {
        enable_metadata: true,
        ..database_config("MetadataMigrationKey")
    };
    let issued = issue(&service, &actor, &config, Some(json!({ "legacy": true }))).await;
    let mut legacy = store
        .find_api_key(&issued.api_key.id)
        .await
        .unwrap()
        .unwrap();
    legacy.metadata = Some(json!(r#"{"legacy":true}"#));
    store.update_api_key(legacy).await.unwrap();

    let returned = service
        .get_api_key(&actor, &config, &issued.api_key.id)
        .await
        .unwrap();
    assert_eq!(returned.metadata, Some(json!({ "legacy": true })));
    let persisted = store
        .find_api_key(&issued.api_key.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.metadata, returned.metadata);
}

#[tokio::test]
async fn database_claims_honor_the_configuration_wide_rate_limit_disable() {
    let (_, service, actor) = fixture().await;
    let config = ApiKeyConfiguration {
        rate_limit: ApiKeyRateLimitConfig {
            enabled: false,
            ..ApiKeyRateLimitConfig::default()
        },
        ..database_config("GloballyUnlimitedKey")
    };
    let issued = issue(&service, &actor, &config, None).await;

    for _ in 0..2 {
        let verified = service
            .verify_api_key(&issued.key, std::slice::from_ref(&config), None, None)
            .await
            .unwrap();
        assert_eq!(verified.api_key.request_count, 0);
        assert!(verified.api_key.last_request.is_some());
    }
}

async fn fixture() -> (Arc<MemoryStore>, AuthService, SessionWithUser) {
    let store = Arc::new(MemoryStore::default());
    let mut auth = AuthConfig::new([b'S'; 32]).unwrap();
    auth.add_plugin(UsernamePlugin::default()).unwrap();
    let service = AuthService::new(store.clone(), auth);
    service
        .provision_password_user(NewPasswordUser {
            username: "storage_owner".into(),
            name: "Storage Owner".into(),
            email: Some("storage-owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let actor = service
        .sign_in_username(
            "storage_owner",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    (store, service, actor.session)
}

fn database_config(key: &str) -> ApiKeyConfiguration {
    ApiKeyConfiguration {
        key_generator: Some(Arc::new(FixedGenerator(key.into()))),
        ..ApiKeyConfiguration::default()
    }
}

async fn issue(
    service: &AuthService,
    actor: &SessionWithUser,
    config: &ApiKeyConfiguration,
    metadata: Option<serde_json::Value>,
) -> lucid_auth::IssuedApiKey {
    service
        .issue_api_key(
            actor,
            config,
            NewApiKey {
                config_id: config.config_id.clone(),
                name: None,
                prefix: None,
                expires_at: None,
                permissions: None,
                metadata,
                remaining: None,
                refill_amount: None,
                refill_interval: None,
                rate_limit_enabled: true,
                rate_limit_time_window: Some(86_400_000),
                rate_limit_max: Some(0),
            },
        )
        .await
        .unwrap()
}

struct FixedGenerator(String);

#[async_trait]
impl ApiKeyGenerator for FixedGenerator {
    async fn generate(&self, _length: usize, _prefix: Option<&str>) -> Result<String, AuthError> {
        Ok(self.0.clone())
    }
}
