use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    ApiKeyConfiguration, ApiKeyError, ApiKeyPlugin, AuthConfig, AuthError, AuthService,
    MemoryStore, NewApiKey, NewPasswordUser, UsernamePlugin,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;

async fn application() -> (Router, Arc<AuthService>, ApiKeyConfiguration) {
    let mut config = AuthConfig::new([121_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    config.add_plugin(UsernamePlugin::default()).unwrap();
    let api_keys = ApiKeyConfiguration {
        enable_metadata: true,
        enable_session_for_api_keys: true,
        default_permissions: Some(BTreeMap::from([("documents".into(), vec!["read".into()])])),
        ..ApiKeyConfiguration::default()
    };
    config
        .add_plugin(ApiKeyPlugin::new(api_keys.clone()))
        .unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    service
        .provision_password_user(NewPasswordUser {
            username: "api_owner".into(),
            name: "API Owner".into(),
            email: Some("api-owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    (lucid_auth::axum::router(service.clone()), service, api_keys)
}

async fn json_request(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    cookie: Option<&str>,
    api_key: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::ORIGIN, "http://localhost");
    if body.is_some() {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if let Some(api_key) = api_key {
        request = request.header("x-api-key", api_key);
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}

async fn owner_cookie(app: &Router) -> String {
    let (status, headers, _) = json_request(
        app,
        "POST",
        "/api/auth/sign-in/username",
        Some(json!({
            "username": "api_owner",
            "password": "correct horse battery staple"
        })),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn official_api_key_http_lifecycle_and_header_session_match() {
    let (app, service, configuration) = application().await;
    let cookie = owner_cookie(&app).await;
    let (id, key) = create_api_key(&app, &cookie).await;
    assert_lookup_and_pagination(&app, &cookie, &id).await;
    assert_verification_and_header_session(&app, &service, &configuration, &id, &key).await;
    assert_update_disable_and_delete(&app, &service, &configuration, &cookie, &id, &key).await;
}

async fn create_api_key(app: &Router, cookie: &str) -> (String, String) {
    let (status, _, created) = json_request(
        app,
        "POST",
        "/api/auth/api-key/create",
        Some(json!({
            "name": "Conformance key",
            "prefix": "conf_",
            "expiresIn": 86_400,
            "metadata": { "environment": "test" }
        })),
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert!(created["id"].is_string());
    assert!(created["key"].as_str().unwrap().starts_with("conf_"));
    assert_eq!(created["configId"], "default");
    assert_eq!(created["permissions"]["documents"], json!(["read"]));
    assert_eq!(created["metadata"]["environment"], "test");
    assert!(created.get("keyHash").is_none());
    (
        created["id"].as_str().unwrap().to_owned(),
        created["key"].as_str().unwrap().to_owned(),
    )
}

async fn assert_lookup_and_pagination(app: &Router, cookie: &str, id: &str) {
    let (status, _, fetched) = json_request(
        app,
        "GET",
        &format!("/api/auth/api-key/get?id={id}"),
        None,
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched["id"], id);
    assert!(fetched.get("key").is_none());

    let (status, _, listed) = json_request(
        app,
        "GET",
        "/api/auth/api-key/list?limit=1&offset=0&sortBy=createdAt&sortDirection=desc",
        None,
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["total"], 1);
    assert_eq!(listed["limit"], 1);
    assert_eq!(listed["offset"], 0);
    assert!(listed["apiKeys"][0].get("key").is_none());
}

async fn assert_verification_and_header_session(
    app: &Router,
    service: &AuthService,
    configuration: &ApiKeyConfiguration,
    id: &str,
    key: &str,
) {
    let allowed = BTreeMap::from([("documents".into(), vec!["read".into()])]);
    service
        .verify_api_key(
            key,
            std::slice::from_ref(configuration),
            None,
            Some(&allowed),
        )
        .await
        .unwrap();
    let denied = BTreeMap::from([("documents".into(), vec!["write".into()])]);
    assert!(matches!(
        service
            .verify_api_key(
                key,
                std::slice::from_ref(configuration),
                None,
                Some(&denied)
            )
            .await,
        Err(AuthError::ApiKey(ApiKeyError::PermissionDenied))
    ));

    let (status, _, session) =
        json_request(app, "GET", "/api/auth/get-session", None, None, Some(key)).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["user"]["email"], "api-owner@example.com");
    assert_eq!(session["session"]["id"], id);
}

async fn assert_update_disable_and_delete(
    app: &Router,
    service: &AuthService,
    configuration: &ApiKeyConfiguration,
    cookie: &str,
    id: &str,
    key: &str,
) {
    let (status, _, updated) = json_request(
        app,
        "POST",
        "/api/auth/api-key/update",
        Some(json!({ "keyId": id, "name": "Updated", "enabled": false })),
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["name"], "Updated");
    assert_eq!(updated["enabled"], false);

    assert!(matches!(
        service
            .verify_api_key(key, std::slice::from_ref(configuration), None, None)
            .await,
        Err(AuthError::ApiKey(ApiKeyError::Disabled))
    ));

    let (status, _, _) = json_request(
        app,
        "POST",
        "/api/auth/api-key/delete",
        Some(json!({ "keyId": id })),
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn client_requests_cannot_set_server_only_api_key_fields() {
    let (app, _, _) = application().await;
    let cookie = owner_cookie(&app).await;
    let (status, _, body) = json_request(
        &app,
        "POST",
        "/api/auth/api-key/create",
        Some(json!({ "remaining": 10 })),
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "SERVER_ONLY_PROPERTY");
}

#[tokio::test]
async fn rate_limit_verification_returns_compatible_retry_metadata() {
    let (app, service, configuration) = application().await;
    let cookie = owner_cookie(&app).await;
    let (_, key) = create_api_key(&app, &cookie).await;
    for _ in 0..10 {
        service
            .verify_api_key(&key, std::slice::from_ref(&configuration), None, None)
            .await
            .unwrap();
    }
    assert!(matches!(
        service
            .verify_api_key(&key, std::slice::from_ref(&configuration), None, None)
            .await,
        Err(AuthError::ApiKey(ApiKeyError::RateLimited {
            retry_after_milliseconds
        })) if retry_after_milliseconds > 0
    ));
}

#[tokio::test]
async fn concurrent_verification_never_exceeds_rate_or_usage_limits() {
    let mut auth = AuthConfig::new([122_u8; 32]).unwrap();
    let configuration = ApiKeyConfiguration {
        rate_limit: lucid_auth::ApiKeyRateLimitConfig {
            enabled: true,
            time_window_milliseconds: 60_000,
            max_requests: 8,
        },
        ..ApiKeyConfiguration::default()
    };
    auth.add_plugin(ApiKeyPlugin::new(configuration.clone()))
        .unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), auth));
    service
        .provision_password_user(NewPasswordUser {
            username: "atomic_owner".into(),
            name: "Atomic Owner".into(),
            email: Some("atomic@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let actor = service
        .sign_in_username(
            "atomic_owner",
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
                remaining: Some(64),
                refill_amount: None,
                refill_interval: None,
                rate_limit_enabled: true,
                rate_limit_time_window: Some(60_000),
                rate_limit_max: Some(8),
            },
        )
        .await
        .unwrap();
    let mut claims = Vec::new();
    for _ in 0..64 {
        let service = service.clone();
        let configuration = configuration.clone();
        let key = issued.key.clone();
        claims.push(tokio::spawn(async move {
            service
                .verify_api_key(&key, &[configuration], Some("default"), None)
                .await
        }));
    }
    let mut allowed = 0;
    let mut limited = 0;
    for claim in claims {
        match claim.await.unwrap() {
            Ok(_) => allowed += 1,
            Err(AuthError::ApiKey(ApiKeyError::RateLimited { .. })) => limited += 1,
            result => panic!("unexpected API-key claim result: {result:?}"),
        }
    }
    assert_eq!(allowed, 8);
    assert_eq!(limited, 56);
}
