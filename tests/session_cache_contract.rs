use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AccessStore, AuthConfig, AuthService, CookieCacheStrategy, MemorySecondaryStorage, MemoryStore,
    RateLimitRequest, SecondaryStorage, SessionStorageMode,
};
use serde_json::{Value, json};
use std::time::Duration as StdDuration;
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;

const SECRET: [u8; 32] = [82; 32];

#[tokio::test]
async fn all_cookie_cache_strategies_bind_to_the_primary_token_and_allow_bypass() {
    for strategy in [
        CookieCacheStrategy::Compact,
        CookieCacheStrategy::Jwt,
        CookieCacheStrategy::Jwe,
    ] {
        let (service, app) = app(strategy, SessionStorageMode::Database, None, false);
        let first = sign_up(&app, "first@example.com").await;
        assert!(first.cookies.contains_key("better-auth.session_data"));
        let first_token = first.body["token"].as_str().unwrap();

        service.sign_out(first_token).await.unwrap();
        let cached = get_session(&app, &first.cookies, "").await;
        assert_eq!(cached.status, StatusCode::OK);
        assert_eq!(cached.body["user"]["email"], "first@example.com");

        let bypassed = get_session(&app, &first.cookies, "?disableCookieCache=true").await;
        assert_eq!(bypassed.body, Value::Null);
        assert_eq!(bypassed.cookies["better-auth.session_data"], "");

        let second = sign_up(&app, "second@example.com").await;
        let mut rebound = first.cookies.clone();
        rebound.insert(
            "better-auth.session_token".into(),
            second.cookies["better-auth.session_token"].clone(),
        );
        let rebound = get_session(&app, &rebound, "").await;
        assert_eq!(rebound.body["user"]["email"], "second@example.com");
    }
}

#[tokio::test]
async fn stateless_cache_and_secondary_storage_modes_follow_better_auth_authority() {
    let (_, stateless) = app(
        CookieCacheStrategy::Compact,
        SessionStorageMode::Stateless,
        None,
        false,
    );
    let signed_up = sign_up(&stateless, "stateless@example.com").await;
    let session = get_session(&stateless, &signed_up.cookies, "").await;
    assert_eq!(session.body["user"]["email"], "stateless@example.com");

    let primary = Arc::new(MemoryStore::default());
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let (service, app) = app_with_store(
        CookieCacheStrategy::Compact,
        SessionStorageMode::Database,
        Some(secondary),
        false,
        primary.clone(),
    );
    let signed_up = sign_up(&app, "secondary@example.com").await;
    let token = signed_up.body["token"].as_str().unwrap();
    let user_id = uuid::Uuid::parse_str(signed_up.body["user"]["id"].as_str().unwrap()).unwrap();
    assert!(primary.list_sessions(user_id).await.unwrap().is_empty());
    assert!(service.session(token).await.unwrap().is_some());
    service.sign_out(token).await.unwrap();
    assert!(service.session(token).await.unwrap().is_none());
}

#[tokio::test]
async fn preserved_database_sessions_are_expired_when_secondary_sessions_are_revoked() {
    let primary = Arc::new(MemoryStore::default());
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let (service, app) = app_with_store(
        CookieCacheStrategy::Compact,
        SessionStorageMode::Database,
        Some(secondary),
        true,
        primary.clone(),
    );
    let signed_up = sign_up(&app, "preserved@example.com").await;
    let token = signed_up.body["token"].as_str().unwrap();
    let user_id = uuid::Uuid::parse_str(signed_up.body["user"]["id"].as_str().unwrap()).unwrap();
    assert_eq!(primary.list_sessions(user_id).await.unwrap().len(), 1);

    service.sign_out(token).await.unwrap();
    let preserved = primary.list_sessions(user_id).await.unwrap();
    assert_eq!(preserved.len(), 1);
    assert!(preserved[0].expires_at <= chrono::Utc::now());
    assert!(service.session(token).await.unwrap().is_none());
}

#[tokio::test]
async fn session_listing_and_revocation_use_the_better_auth_opaque_token() {
    let (_, app) = app(
        CookieCacheStrategy::Compact,
        SessionStorageMode::Database,
        None,
        false,
    );
    let first = sign_up(&app, "sessions@example.com").await;
    let target = first.body["token"].as_str().unwrap().to_owned();
    let actor = sign_in(&app, "sessions@example.com").await;
    let listed = request_with_cookies(
        &app,
        Request::builder()
            .uri("/api/auth/list-sessions")
            .body(Body::empty())
            .unwrap(),
        &actor.cookies,
    )
    .await;
    assert!(listed.body.as_array().unwrap().iter().any(|session| {
        session["token"] == target && session["id"].as_str() != Some(target.as_str())
    }));

    let revoked = request_with_cookies(
        &app,
        Request::builder()
            .method("POST")
            .uri("/api/auth/revoke-session")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "token": target }).to_string()))
            .unwrap(),
        &actor.cookies,
    )
    .await;
    assert_eq!(revoked.body, json!({ "status": true }));
    assert_eq!(
        get_session(&app, &first.cookies, "?disableCookieCache=true")
            .await
            .body,
        Value::Null
    );
}

#[tokio::test]
async fn configured_secondary_storage_is_the_default_atomic_rate_limit_store() {
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let mut config = AuthConfig::new(SECRET).unwrap();
    config.rate_limit.enabled = true;
    config.rate_limit.window = 60;
    config.rate_limit.max = 1;
    config.secondary_storage = Some(secondary.clone());
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);
    let request = RateLimitRequest {
        method: "GET".into(),
        path: "/ordinary".into(),
        query: None,
        headers: BTreeMap::new(),
    };
    assert!(
        service
            .consume_rate_limit_request(&request, Some("192.0.2.4"))
            .await
            .unwrap()
            .unwrap()
            .allowed
    );
    let denied = service
        .consume_rate_limit_request(&request, Some("192.0.2.4"))
        .await
        .unwrap()
        .unwrap();
    assert!(!denied.allowed);
    assert_eq!(denied.retry_after, Some(60));
    assert_eq!(
        secondary
            .get("rate-limit:192.0.2.4|/ordinary:count")
            .await
            .unwrap()
            .as_deref(),
        Some("2")
    );
}

#[tokio::test]
async fn stateless_refresh_expiry_and_version_invalidation_are_deterministic() {
    let mut stateless_config = AuthConfig::new(SECRET).unwrap();
    stateless_config.email_and_password.enabled = true;
    stateless_config.set_base_url("http://localhost").unwrap();
    stateless_config.session.storage_mode = SessionStorageMode::Stateless;
    stateless_config.session.cookie_cache.enabled = true;
    stateless_config.session.cookie_cache.max_age = chrono::Duration::seconds(2);
    stateless_config.session.cookie_cache.refresh_cache = lucid_auth::CookieCacheRefresh::Enabled;
    let stateless_service = Arc::new(AuthService::new(
        Arc::new(MemoryStore::default()),
        stateless_config,
    ));
    let stateless = lucid_auth::axum::router(stateless_service);
    let signed_up = sign_up(&stateless, "refresh@example.com").await;
    let original_cache = signed_up.cookies["better-auth.session_data"].clone();
    tokio::time::sleep(StdDuration::from_millis(1_700)).await;
    let refreshed = get_session(&stateless, &signed_up.cookies, "").await;
    assert_eq!(refreshed.body["user"]["email"], "refresh@example.com");
    assert_ne!(
        refreshed.cookies["better-auth.session_data"],
        original_cache
    );

    let expiring = sign_up(&stateless, "expiry@example.com").await;
    tokio::time::sleep(StdDuration::from_millis(2_100)).await;
    let expired = get_session(&stateless, &expiring.cookies, "").await;
    assert_eq!(expired.body, Value::Null);
    assert_eq!(expired.cookies["better-auth.session_data"], "");

    let store = Arc::new(MemoryStore::default());
    let mut version_one = AuthConfig::new(SECRET).unwrap();
    version_one.email_and_password.enabled = true;
    version_one.set_base_url("http://localhost").unwrap();
    version_one.session.cookie_cache.enabled = true;
    version_one.session.cookie_cache.version = "one".into();
    let first_service = Arc::new(AuthService::new(store.clone(), version_one));
    let first_app = lucid_auth::axum::router(first_service);
    let old = sign_up(&first_app, "version@example.com").await;

    let mut version_two = AuthConfig::new(SECRET).unwrap();
    version_two.email_and_password.enabled = true;
    version_two.set_base_url("http://localhost").unwrap();
    version_two.session.cookie_cache.enabled = true;
    version_two.session.cookie_cache.version = "two".into();
    let second_service = Arc::new(AuthService::new(store, version_two));
    let second_app = lucid_auth::axum::router(second_service);
    let replaced = get_session(&second_app, &old.cookies, "").await;
    assert_eq!(replaced.body["user"]["email"], "version@example.com");
    assert_ne!(
        replaced.cookies["better-auth.session_data"],
        old.cookies["better-auth.session_data"]
    );
}

fn app(
    strategy: CookieCacheStrategy,
    mode: SessionStorageMode,
    secondary: Option<Arc<MemorySecondaryStorage>>,
    preserve: bool,
) -> (Arc<AuthService>, Router) {
    app_with_store(
        strategy,
        mode,
        secondary,
        preserve,
        Arc::new(MemoryStore::default()),
    )
}

fn app_with_store(
    strategy: CookieCacheStrategy,
    mode: SessionStorageMode,
    secondary: Option<Arc<MemorySecondaryStorage>>,
    preserve: bool,
    store: Arc<MemoryStore>,
) -> (Arc<AuthService>, Router) {
    let mut config = AuthConfig::new(SECRET).unwrap();
    config.email_and_password.enabled = true;
    config.set_base_url("http://localhost").unwrap();
    config.session.cookie_cache.enabled = true;
    config.session.cookie_cache.strategy = strategy;
    config.session.storage_mode = mode;
    config.session.store_session_in_database = preserve;
    config.session.preserve_session_in_database = preserve;
    config.secondary_storage = secondary.map(|storage| storage as Arc<_>);
    let service = Arc::new(AuthService::new(store, config));
    (service.clone(), lucid_auth::axum::router(service))
}

struct HttpResult {
    status: StatusCode,
    body: Value,
    cookies: BTreeMap<String, String>,
}

async fn sign_up(app: &Router, email: &str) -> HttpResult {
    request(
        app,
        Request::builder()
            .method("POST")
            .uri("/api/auth/sign-up/email")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "name": "Cookie User",
                    "email": email,
                    "password": "correct horse battery staple"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
}

async fn sign_in(app: &Router, email: &str) -> HttpResult {
    request(
        app,
        Request::builder()
            .method("POST")
            .uri("/api/auth/sign-in/email")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "email": email,
                    "password": "correct horse battery staple"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
}

async fn get_session(app: &Router, cookies: &BTreeMap<String, String>, query: &str) -> HttpResult {
    request_with_cookies(
        app,
        Request::builder()
            .uri(format!("/api/auth/get-session{query}"))
            .body(Body::empty())
            .unwrap(),
        cookies,
    )
    .await
}

async fn request_with_cookies(
    app: &Router,
    mut request_value: Request<Body>,
    cookies: &BTreeMap<String, String>,
) -> HttpResult {
    let cookie = cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    request_value
        .headers_mut()
        .insert(header::COOKIE, cookie.parse().unwrap());
    request_value
        .headers_mut()
        .insert(header::ORIGIN, "http://localhost".parse().unwrap());
    request(app, request_value).await
}

async fn request(app: &Router, request: Request<Body>) -> HttpResult {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| (name.into(), value.into()))
        .collect();
    let body =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    HttpResult {
        status,
        body,
        cookies,
    }
}
