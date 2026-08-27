use async_trait::async_trait;
use lucid_auth::{
    ApiKeyConfiguration, ApiKeyError, ApiKeyGenerator, ApiKeyPlugin, ApiKeyRateLimitConfig,
    ApiKeyStorage, AuthConfig, AuthError, AuthService, MemorySecondaryStorage, MemoryStore,
    NewApiKey, NewPasswordUser, SecondaryStorage, UsernamePlugin,
};
use std::sync::Arc;

#[tokio::test]
async fn deferred_secondary_usage_returns_optimistic_state_then_persists_it() {
    let (service, configuration, secondary, key) = deferred_fixture().await;

    let first = service
        .verify_api_key(&key, std::slice::from_ref(&configuration), None, None)
        .await
        .unwrap();
    assert_eq!(first.api_key.remaining, Some(1));
    wait_for_remaining(secondary.as_ref(), Some(1)).await;

    let second = service
        .verify_api_key(&key, std::slice::from_ref(&configuration), None, None)
        .await
        .unwrap();
    assert_eq!(second.api_key.remaining, Some(0));
    wait_for_remaining(secondary.as_ref(), Some(0)).await;

    assert!(matches!(
        service
            .verify_api_key(&key, &[configuration], None, None)
            .await,
        Err(AuthError::ApiKey(ApiKeyError::UsageExceeded))
    ));
    wait_for_deletion(secondary.as_ref()).await;
}

async fn deferred_fixture() -> (
    AuthService,
    ApiKeyConfiguration,
    Arc<MemorySecondaryStorage>,
    String,
) {
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let configuration = ApiKeyConfiguration {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(secondary.clone()),
        disable_key_hashing: true,
        defer_updates: true,
        rate_limit: ApiKeyRateLimitConfig {
            enabled: false,
            ..ApiKeyRateLimitConfig::default()
        },
        key_generator: Some(Arc::new(FixedGenerator)),
        ..ApiKeyConfiguration::default()
    };
    let mut auth = AuthConfig::new([b'D'; 32]).unwrap();
    auth.add_plugin(UsernamePlugin::default()).unwrap();
    auth.add_plugin(ApiKeyPlugin::new(configuration.clone()))
        .unwrap();
    let service = AuthService::new(Arc::new(MemoryStore::default()), auth);
    service
        .provision_password_user(NewPasswordUser {
            username: "deferred_owner".into(),
            name: "Deferred Owner".into(),
            email: Some("deferred@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let actor = service
        .sign_in_username(
            "deferred_owner",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    let issued = service
        .issue_api_key(
            &actor.session,
            &configuration,
            NewApiKey {
                config_id: "default".into(),
                name: None,
                prefix: None,
                expires_at: None,
                permissions: None,
                metadata: None,
                remaining: Some(2),
                refill_amount: None,
                refill_interval: None,
                rate_limit_enabled: false,
                rate_limit_time_window: None,
                rate_limit_max: None,
            },
        )
        .await
        .unwrap();
    (service, configuration, secondary, issued.key)
}

async fn wait_for_remaining(storage: &dyn SecondaryStorage, expected: Option<i64>) {
    for _ in 0..100 {
        if storage
            .get("api-key:DeferredQuotaKey")
            .await
            .unwrap()
            .and_then(|value| serde_json::from_str::<serde_json::Value>(&value).ok())
            .and_then(|value| value["remaining"].as_i64())
            == expected
        {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("deferred API-key usage was not persisted");
}

async fn wait_for_deletion(storage: &dyn SecondaryStorage) {
    for _ in 0..100 {
        if storage
            .get("api-key:DeferredQuotaKey")
            .await
            .unwrap()
            .is_none()
        {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("exhausted deferred API key was not deleted");
}

struct FixedGenerator;

#[async_trait]
impl ApiKeyGenerator for FixedGenerator {
    async fn generate(&self, _length: usize, _prefix: Option<&str>) -> Result<String, AuthError> {
        Ok("DeferredQuotaKey".into())
    }
}
