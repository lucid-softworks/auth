mod api_key_advanced_support;

use api_key_advanced_support::*;
use axum::http::{StatusCode, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use lucid_auth::{
    ApiKeyConfiguration, ApiKeyError, ApiKeyGetterValue, ApiKeyPlugin, ApiKeyStorage, AuthConfig,
    AuthError, AuthService, DatabaseIdGenerationSize, MemorySecondaryStorage, MemoryStore,
    SecondaryStorage, UsernamePlugin,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn secondary_only_uses_plaintext_storage_and_special_id_callback() {
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let id_callback = Arc::new(IdCallback::default());
    let generator = Arc::new(FixedGenerator("PlaintextOracleKey".into()));
    let configuration = ApiKeyConfiguration {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(secondary.clone()),
        disable_key_hashing: true,
        default_key_length: 12,
        key_generator: Some(generator),
        ..ApiKeyConfiguration::default()
    };
    let (app, _) = application(configuration, Some(id_callback.clone())).await;
    let cookie = owner_cookie(&app).await;
    id_callback.calls.lock().unwrap().clear();

    let (status, created) = json_request(
        &app,
        "POST",
        "/api/auth/api-key/create",
        Some(json!({ "name": "secondary", "prefix": "ignored_" })),
        [(header::COOKIE.as_str(), cookie.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["key"], "PlaintextOracleKey");
    let id = created["id"].as_str().unwrap();
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    assert_eq!(
        *id_callback.calls.lock().unwrap(),
        [("apikey".into(), DatabaseIdGenerationSize::Undefined)]
    );
    let stored = secondary
        .get("api-key:PlaintextOracleKey")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&stored).unwrap()["key"],
        "PlaintextOracleKey"
    );
    assert!(
        secondary
            .get(&format!("api-key:by-id:{id}"))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn request_getter_and_validator_match_callback_counts_and_order() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let secondary = Arc::new(ObservableStorage::new(events.clone()));
    let getter = Arc::new(RecordingGetter::new(events.clone()));
    let validator = Arc::new(RecordingValidator::new(events.clone()));
    let configuration = ApiKeyConfiguration {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(secondary),
        default_key_length: 12,
        enable_session_for_api_keys: true,
        key_generator: Some(Arc::new(FixedGenerator("CallbackOracleKey".into()))),
        key_getter: Some(getter.clone()),
        key_validator: Some(validator.clone()),
        ..ApiKeyConfiguration::default()
    };
    let (app, _) = application(configuration, None).await;
    let cookie = owner_cookie(&app).await;
    let (_, created) = json_request(
        &app,
        "POST",
        "/api/auth/api-key/create",
        Some(json!({ "name": "callbacks", "expiresIn": 86400 })),
        [(header::COOKIE.as_str(), cookie.as_str())],
    )
    .await;
    let key = created["key"].as_str().unwrap().to_owned();
    getter.set(ApiKeyGetterValue::Key(key.clone()));
    events.lock().unwrap().clear();

    let (status, session) = json_request(
        &app,
        "GET",
        "/api/auth/get-session",
        None,
        [(header::USER_AGENT.as_str(), "api-key-contract/1.0")],
    )
    .await;
    assert_mocked_session(status, &session, &created, &key);
    assert_callback_order(&events.lock().unwrap());
    assert_callback_rejections(&app, &getter, &validator).await;
}

fn assert_mocked_session(status: StatusCode, session: &Value, created: &Value, key: &str) {
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["session"]["token"], key);
    assert_eq!(session["session"]["id"], created["id"]);
    assert_eq!(session["session"]["expiresAt"], created["expiresAt"]);
    assert_eq!(session["session"]["ipAddress"], "127.0.0.1");
    assert_eq!(session["session"]["userAgent"], "api-key-contract/1.0");
}

fn assert_callback_order(observed: &[String]) {
    assert_eq!(
        observed
            .iter()
            .filter(|event| event.as_str() == "getter:/get-session")
            .count(),
        2
    );
    assert_eq!(
        observed
            .iter()
            .filter(|event| event.starts_with("validator:"))
            .count(),
        1
    );
    assert!(
        observed
            .iter()
            .position(|event| event.starts_with("validator:"))
            .unwrap()
            < observed
                .iter()
                .position(|event| event.starts_with("storage:api-key:"))
                .unwrap()
    );
}

async fn assert_callback_rejections(
    app: &axum::Router,
    getter: &RecordingGetter,
    validator: &RecordingValidator,
) {
    validator.set(false);
    let (status, body) = json_request(
        app,
        "GET",
        "/api/auth/get-session",
        None,
        std::iter::empty::<(&str, &str)>(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "INVALID_API_KEY");

    validator.set(true);
    getter.set(ApiKeyGetterValue::Invalid);
    let (status, body) = json_request(
        app,
        "GET",
        "/api/auth/get-session",
        None,
        std::iter::empty::<(&str, &str)>(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_API_KEY_GETTER_RETURN_TYPE");
    assert_eq!(
        body["message"],
        "API Key getter returned an invalid key type. Expected string."
    );
}

#[tokio::test]
async fn verify_validator_order_depends_on_explicit_config_id() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let secondary = Arc::new(ObservableStorage::new(events.clone()));
    let validator = Arc::new(RecordingValidator::new(events.clone()));
    let configuration = ApiKeyConfiguration {
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(secondary),
        default_key_length: 12,
        key_generator: Some(Arc::new(FixedGenerator("VerifyOrderKey".into()))),
        key_validator: Some(validator.clone()),
        ..ApiKeyConfiguration::default()
    };
    let configurations = [configuration.clone()];
    let (app, service) = application(configuration, None).await;
    let cookie = owner_cookie(&app).await;
    let (_, created) = json_request(
        &app,
        "POST",
        "/api/auth/api-key/create",
        Some(json!({ "name": "order" })),
        [(header::COOKIE.as_str(), cookie.as_str())],
    )
    .await;
    let key = created["key"].as_str().unwrap();

    events.lock().unwrap().clear();
    service
        .verify_api_key(key, &configurations, Some("default"), None)
        .await
        .unwrap();
    let explicit_events = events.lock().unwrap().clone();
    assert!(explicit_events[0].starts_with("validator:/api-key/verify:"));
    assert!(explicit_events[1].starts_with("storage:api-key:"));

    events.lock().unwrap().clear();
    service
        .verify_api_key(key, &configurations, None, None)
        .await
        .unwrap();
    let inferred_events = events.lock().unwrap().clone();
    assert!(inferred_events[0].starts_with("storage:api-key:"));
    assert!(inferred_events[1].starts_with("validator:/api-key/verify:"));

    assert_verify_rejections(&service, &configurations, &validator, key).await;
}

async fn assert_verify_rejections(
    service: &AuthService,
    configurations: &[ApiKeyConfiguration],
    validator: &RecordingValidator,
    key: &str,
) {
    validator.set(false);
    assert!(matches!(
        service
            .verify_api_key(key, configurations, Some("default"), None)
            .await,
        Err(AuthError::ApiKey(
            ApiKeyError::VerificationValidatorRejected
        ))
    ));
    assert!(matches!(
        service
            .verify_api_key(key, configurations, None, None)
            .await,
        Err(AuthError::ApiKey(ApiKeyError::NotFound))
    ));
}

#[tokio::test]
async fn database_fallback_rehydrates_a_missing_secondary_record() {
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let configuration = ApiKeyConfiguration {
        storage: ApiKeyStorage::SecondaryStorage,
        fallback_to_database: true,
        custom_storage: Some(secondary.clone()),
        default_key_length: 12,
        key_generator: Some(Arc::new(FixedGenerator("FallbackOracleKey".into()))),
        ..ApiKeyConfiguration::default()
    };
    let configurations = [configuration.clone()];
    let (app, service) = application(configuration, None).await;
    let cookie = owner_cookie(&app).await;
    let (_, created) = json_request(
        &app,
        "POST",
        "/api/auth/api-key/create",
        Some(json!({ "name": "fallback" })),
        [(header::COOKIE.as_str(), cookie.as_str())],
    )
    .await;
    let key = created["key"].as_str().unwrap();
    let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(key.as_bytes()));
    secondary.delete(&format!("api-key:{hash}")).await.unwrap();

    service
        .verify_api_key(key, &configurations, None, None)
        .await
        .unwrap();
    assert!(
        secondary
            .get(&format!("api-key:{hash}"))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn list_aggregates_distinct_storage_groups_and_filters_raw_config_id() {
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let default = ApiKeyConfiguration {
        key_generator: Some(Arc::new(FixedGenerator("DatabaseListKey".into()))),
        ..ApiKeyConfiguration::default()
    };
    let other = ApiKeyConfiguration {
        config_id: "other".into(),
        storage: ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(secondary),
        key_generator: Some(Arc::new(FixedGenerator("SecondaryListKey".into()))),
        ..ApiKeyConfiguration::default()
    };
    let (app, _) = application_with_configurations(vec![default, other]).await;
    let cookie = owner_cookie(&app).await;
    create_named_key(&app, &cookie, "default").await;
    create_named_key(&app, &cookie, "other").await;

    let (_, all) = json_request(
        &app,
        "GET",
        "/api/auth/api-key/list",
        None,
        [(header::COOKIE.as_str(), cookie.as_str())],
    )
    .await;
    assert_eq!(all["total"], 2);
    assert_eq!(all["apiKeys"].as_array().unwrap().len(), 2);

    let (_, unknown) = json_request(
        &app,
        "GET",
        "/api/auth/api-key/list?configId=missing",
        None,
        [(header::COOKIE.as_str(), cookie.as_str())],
    )
    .await;
    assert_eq!(unknown["total"], 0);
}

async fn create_named_key(app: &axum::Router, cookie: &str, config_id: &str) {
    let (status, body) = json_request(
        app,
        "POST",
        "/api/auth/api-key/create",
        Some(json!({ "configId": config_id, "name": config_id })),
        [(header::COOKIE.as_str(), cookie)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn missing_default_configuration_fails_at_request_time() {
    let mut auth = AuthConfig::new([b'A'; 32]).unwrap();
    auth.set_base_url("http://localhost").unwrap();
    auth.add_plugin(UsernamePlugin::default()).unwrap();
    auth.add_plugin(ApiKeyPlugin::with_configurations(vec![
        ApiKeyConfiguration {
            config_id: "other".into(),
            ..ApiKeyConfiguration::default()
        },
    ]))
    .unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), auth));
    provision(&service).await;
    let app = lucid_auth::axum::router(service);
    let cookie = owner_cookie(&app).await;
    let (status, body) = json_request(
        &app,
        "POST",
        "/api/auth/api-key/create",
        Some(json!({})),
        [(header::COOKIE.as_str(), cookie.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND");
}
