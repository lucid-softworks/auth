use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, AuthStore, BeforeDatabaseHook, DatabaseHookContext,
    DatabaseHooks, DatabaseRecord, MemorySecondaryStorage, MemoryStore, SecondaryStorage,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;

const SECRET: [u8; 32] = [91; 32];

#[tokio::test]
async fn refreshes_at_update_age_but_honors_both_disable_controls() {
    let store = Arc::new(MemoryStore::default());
    let (_, router) = app(store.clone(), false, false, None, None);
    let signed_up = sign_up(&router, "refresh@example.com", true).await;
    let token = signed_up.body["token"].as_str().unwrap();
    make_refresh_due(store.as_ref(), token).await;

    let refreshed = get_session(&router, &signed_up.cookies, "").await;
    assert_eq!(refreshed.status, StatusCode::OK);
    assert!(refreshed.cookies.contains_key("better-auth.session_token"));
    let expires_at = refreshed.body["session"]["expiresAt"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<Utc>>()
        .unwrap();
    assert!(expires_at > Utc::now() + Duration::minutes(55));

    make_refresh_due(store.as_ref(), token).await;
    let disabled = get_session(&router, &signed_up.cookies, "?disableRefresh=true").await;
    assert!(!disabled.cookies.contains_key("better-auth.session_token"));
    assert!(
        disabled.body["session"]["expiresAt"]
            .as_str()
            .unwrap()
            .parse::<chrono::DateTime<Utc>>()
            .unwrap()
            < Utc::now() + Duration::minutes(25)
    );

    let server_store = Arc::new(MemoryStore::default());
    let (_, server_disabled) = app(server_store.clone(), false, true, None, None);
    let session = sign_up(&server_disabled, "disabled@example.com", true).await;
    let server_token = session.body["token"].as_str().unwrap();
    make_refresh_due(server_store.as_ref(), server_token).await;
    let unchanged = get_session(&server_disabled, &session.cookies, "").await;
    assert!(!unchanged.cookies.contains_key("better-auth.session_token"));
}

#[tokio::test]
async fn deferred_get_is_write_free_and_post_performs_the_refresh() {
    let store = Arc::new(MemoryStore::default());
    let (_, app) = app(store.clone(), true, false, None, None);
    let signed_up = sign_up(&app, "deferred@example.com", true).await;
    let token = signed_up.body["token"].as_str().unwrap();
    make_refresh_due(store.as_ref(), token).await;
    let before = store.find_session(token).await.unwrap().unwrap().0;

    let read = get_session(&app, &signed_up.cookies, "").await;
    assert_eq!(read.body["needsRefresh"], true);
    assert_eq!(
        store
            .find_session(token)
            .await
            .unwrap()
            .unwrap()
            .0
            .expires_at,
        before.expires_at
    );

    let refreshed = post_get_session(&app, &signed_up.cookies).await;
    assert_eq!(refreshed.status, StatusCode::OK);
    assert!(refreshed.body.get("needsRefresh").is_none());
    assert!(
        store
            .find_session(token)
            .await
            .unwrap()
            .unwrap()
            .0
            .expires_at
            > before.expires_at + Duration::minutes(30)
    );
    assert!(refreshed.cookies.contains_key("better-auth.session_token"));
}

#[tokio::test]
async fn post_requires_deferred_refresh_with_the_exact_better_auth_error() {
    let store = Arc::new(MemoryStore::default());
    let (_, app) = app(store, false, false, None, None);

    let response = request(
        &app,
        Request::builder()
            .method("POST")
            .uri("/api/auth/get-session")
            .header(header::ORIGIN, "http://localhost")
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        response.body,
        json!({
            "code": "METHOD_NOT_ALLOWED",
            "message": "POST method requires deferSessionRefresh to be enabled in session config"
        })
    );
}

#[tokio::test]
async fn non_remembered_sessions_use_the_marker_and_never_slide() {
    let store = Arc::new(MemoryStore::default());
    let (_, app) = app(store.clone(), false, false, None, None);
    let signed_up = sign_up(&app, "temporary@example.com", false).await;
    let token = signed_up.body["token"].as_str().unwrap();
    assert!(signed_up.cookies.contains_key("better-auth.dont_remember"));
    assert!(
        signed_up
            .set_cookies
            .iter()
            .any(|cookie| cookie.starts_with("better-auth.session_token=")
                && !cookie.contains("Max-Age="))
    );
    let initial = store.find_session(token).await.unwrap().unwrap().0;
    assert!(initial.expires_at > Utc::now() + Duration::hours(23));
    assert!(initial.expires_at < Utc::now() + Duration::hours(25));
    make_refresh_due(store.as_ref(), token).await;
    let before = store.find_session(token).await.unwrap().unwrap().0;

    let response = get_session(&app, &signed_up.cookies, "").await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        store
            .find_session(token)
            .await
            .unwrap()
            .unwrap()
            .0
            .expires_at,
        before.expires_at
    );
    assert!(!response.cookies.contains_key("better-auth.session_token"));
}

#[tokio::test]
async fn refresh_updates_secondary_session_and_active_reference_expiry() {
    let store = Arc::new(MemoryStore::default());
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let (_, app) = app(store, false, false, Some(secondary.clone()), None);
    let signed_up = sign_up(&app, "secondary-refresh@example.com", true).await;
    let token = signed_up.body["token"].as_str().unwrap();
    let user_id = signed_up.body["user"]["id"].as_str().unwrap();
    let mut stored: Value =
        serde_json::from_str(&secondary.get(token).await.unwrap().unwrap()).unwrap();
    let due = Utc::now() + Duration::minutes(20);
    stored["session"]["expiresAt"] = json!(due);
    secondary
        .set(token, stored.to_string(), Some(1_200))
        .await
        .unwrap();
    secondary
        .set(
            &format!("active-sessions-{user_id}"),
            json!([{ "token": token, "expiresAt": due.timestamp_millis() }]).to_string(),
            Some(1_200),
        )
        .await
        .unwrap();

    let response = get_session(&app, &signed_up.cookies, "").await;

    assert_eq!(response.status, StatusCode::OK);
    let refreshed: Value =
        serde_json::from_str(&secondary.get(token).await.unwrap().unwrap()).unwrap();
    let expires_at = refreshed["session"]["expiresAt"]
        .as_str()
        .unwrap()
        .parse::<chrono::DateTime<Utc>>()
        .unwrap();
    assert!(expires_at > Utc::now() + Duration::minutes(55));
    let references: Value = serde_json::from_str(
        &secondary
            .get(&format!("active-sessions-{user_id}"))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(references[0]["expiresAt"], expires_at.timestamp_millis());
}

#[tokio::test]
async fn concurrent_deletion_cannot_be_resurrected_by_refresh() {
    let store = Arc::new(MemoryStore::default());
    let hooks = Arc::new(DeleteBeforeRefresh {
        store: store.clone(),
    });
    let (_, app) = app(store.clone(), false, false, None, Some(hooks));
    let signed_up = sign_up(&app, "race@example.com", true).await;
    let token = signed_up.body["token"].as_str().unwrap();
    make_refresh_due(store.as_ref(), token).await;

    let response = get_session(&app, &signed_up.cookies, "").await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.body,
        json!({ "code": "UNAUTHORIZED", "message": "Failed to get session" })
    );
    assert!(store.find_session(token).await.unwrap().is_none());
    assert_eq!(response.cookies["better-auth.session_token"], "");
    assert_eq!(response.cookies["better-auth.session_data"], "");
    assert_eq!(response.cookies["better-auth.dont_remember"], "");
}

struct DeleteBeforeRefresh {
    store: Arc<MemoryStore>,
}

#[async_trait]
impl DatabaseHooks for DeleteBeforeRefresh {
    async fn before_update(
        &self,
        record: &DatabaseRecord,
        _context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseHook, AuthError> {
        if let DatabaseRecord::Session(session) = record {
            self.store.delete_session(&session.token).await?;
        }
        Ok(BeforeDatabaseHook::Continue)
    }
}

fn app(
    store: Arc<MemoryStore>,
    defer: bool,
    disable: bool,
    secondary: Option<Arc<MemorySecondaryStorage>>,
    hooks: Option<Arc<dyn DatabaseHooks>>,
) -> (Arc<AuthService>, Router) {
    let mut config = AuthConfig::new(SECRET).unwrap();
    config.email_and_password.enabled = true;
    config.set_base_url("http://localhost").unwrap();
    config.session_ttl = Duration::hours(1);
    config.session.update_age = Duration::minutes(30);
    config.session.defer_session_refresh = defer;
    config.session.disable_session_refresh = disable;
    config.secondary_storage = secondary.map(|storage| storage as Arc<_>);
    config.database_hooks = hooks;
    let service = Arc::new(AuthService::new(store, config));
    (service.clone(), lucid_auth::axum::router(service))
}

async fn make_refresh_due(store: &MemoryStore, token: &str) {
    let now = Utc::now();
    store
        .refresh_session(token, now + Duration::minutes(20), now)
        .await
        .unwrap()
        .unwrap();
}

async fn sign_up(app: &Router, email: &str, remember_me: bool) -> HttpResult {
    request(
        app,
        Request::builder()
            .method("POST")
            .uri("/api/auth/sign-up/email")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "name": "Refresh User",
                    "email": email,
                    "password": "correct horse battery staple",
                    "rememberMe": remember_me
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
}

async fn get_session(app: &Router, cookies: &BTreeMap<String, String>, query: &str) -> HttpResult {
    session_request(app, cookies, "GET", query).await
}

async fn post_get_session(app: &Router, cookies: &BTreeMap<String, String>) -> HttpResult {
    session_request(app, cookies, "POST", "").await
}

async fn session_request(
    app: &Router,
    cookies: &BTreeMap<String, String>,
    method: &str,
    query: &str,
) -> HttpResult {
    let cookie = cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    request(
        app,
        Request::builder()
            .method(method)
            .uri(format!("/api/auth/get-session{query}"))
            .header(header::COOKIE, cookie)
            .header(header::ORIGIN, "http://localhost")
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

struct HttpResult {
    status: StatusCode,
    body: Value,
    cookies: BTreeMap<String, String>,
    set_cookies: Vec<String>,
}

async fn request(app: &Router, request: Request<Body>) -> HttpResult {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let set_cookies: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    let cookies = set_cookies
        .iter()
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
        set_cookies,
    }
}
