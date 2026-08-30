use axum::{
    Json, Router,
    body::Body,
    extract::{RawQuery, State},
    http::{Request, StatusCode, header},
    routing::{get, post},
};
use http_body_util::BodyExt as _;
use josekit::{
    jwk::Jwk,
    jws::{self, JwsHeader, RS256},
};
use lucid_auth::{
    AuthConfig, AuthService, DashOptions, DashPlugin, InfraConnectionOptions, MemoryStore,
    NewPasswordUser,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt as _;

#[derive(Clone)]
struct ManagedApi {
    public_key: Value,
    jti_checks: Arc<AtomicUsize>,
    event_queries: Arc<Mutex<Vec<String>>>,
}

async fn jwks(State(api): State<ManagedApi>) -> Json<Value> {
    Json(json!({"keys": [api.public_key]}))
}

async fn check_jti(State(api): State<ManagedApi>) -> Json<Value> {
    api.jti_checks.fetch_add(1, Ordering::SeqCst);
    Json(json!({"valid": true}))
}

async fn user_events(State(api): State<ManagedApi>, RawQuery(query): RawQuery) -> Json<Value> {
    api.event_queries
        .lock()
        .unwrap()
        .push(format!("user?{}", query.unwrap_or_default()));
    Json(json!({
        "events": [
            {
                "eventType": "user_signed_in",
                "eventData": {"userId": "ignored-by-user-scope"},
                "eventKey": "user-1",
                "projectId": "project-1",
                "createdAt": "2026-08-30T08:00:00Z",
                "updatedAt": "2026-08-30T08:01:00Z",
                "ageInMinutes": 2,
                "ipAddress": "203.0.113.1",
                "city": null
            },
            {
                "eventType": "password_changed",
                "eventData": {"userId": "ignored-by-user-scope"},
                "eventKey": "user-1",
                "projectId": "project-1",
                "createdAt": "2026-08-30T09:00:00Z",
                "updatedAt": "2026-08-30T09:01:00Z"
            }
        ],
        "total": 20,
        "limit": 7,
        "offset": 3
    }))
}

async fn fixture() -> (
    Router,
    Jwk,
    Arc<AtomicUsize>,
    Arc<Mutex<Vec<String>>>,
    tokio::task::JoinHandle<()>,
) {
    let mut private_key = Jwk::generate_rsa_key(2_048).unwrap();
    private_key.set_key_id("dash-contract");
    private_key.set_algorithm("RS256");
    let mut public_key = private_key.to_public_key().unwrap();
    public_key.set_key_id("dash-contract");
    public_key.set_algorithm("RS256");
    let jti_checks = Arc::new(AtomicUsize::new(0));
    let event_queries = Arc::new(Mutex::new(Vec::new()));
    let managed = Router::new()
        .route("/api/auth/jwks", get(jwks))
        .route("/api/auth/check-jti", post(check_jti))
        .route("/events/user", get(user_events))
        .with_state(ManagedApi {
            public_key: serde_json::to_value(public_key).unwrap(),
            jti_checks: jti_checks.clone(),
            event_queries: event_queries.clone(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, managed).await.unwrap() });

    let mut config = AuthConfig::new([b'D'; 32]).unwrap();
    config.email_and_password.enabled = true;
    config
        .add_plugin(DashPlugin::new(DashOptions {
            connection: InfraConnectionOptions {
                api_url: Some(format!("http://{address}")),
                api_key: Some("managed-contract-key".into()),
                ..InfraConnectionOptions::default()
            },
            ..DashOptions::default()
        }))
        .unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: Some("luna@example.com".into()),
            password: "password".into(),
            role: "user".into(),
        })
        .await
        .unwrap();
    (
        lucid_auth::axum::router(service),
        private_key,
        jti_checks,
        event_queries,
        server,
    )
}

fn token(private_key: &Jwk, age_seconds: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = json!({
        "iat": now - age_seconds,
        "exp": now + 3_600,
        "jti": "dash-contract-jti",
        "apiKeyHash": hex::encode(Sha256::digest(b"managed-contract-key")),
    });
    let mut header = JwsHeader::new();
    header.set_algorithm("RS256");
    header.set_key_id("dash-contract");
    jws::serialize_compact(
        &serde_json::to_vec(&claims).unwrap(),
        &header,
        &RS256.signer_from_jwk(private_key).unwrap(),
    )
    .unwrap()
}

async fn request(app: &Router, uri: &str, token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::get(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

async fn local_cookie(app: &Router) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/email")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"email": "luna@example.com", "password": "password"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn core_routes_use_managed_jwt_policy_and_return_dash_shapes() {
    let (app, private_key, jti_checks, _event_queries, server) = fixture().await;
    let old_token = token(&private_key, 60);

    let config = request(&app, "/api/auth/dash/config", &old_token).await;
    assert_eq!(config.status(), StatusCode::OK);
    let config = json_body(config).await;
    assert_eq!(config["version"], "1.7.1");
    assert!(!config.to_string().contains("managed-contract-key"));
    assert_eq!(jti_checks.load(Ordering::SeqCst), 1);

    let validate = request(&app, "/api/auth/dash/validate", &old_token).await;
    assert_eq!(validate.status(), StatusCode::OK);
    assert_eq!(json_body(validate).await, json!({"valid": true}));
    assert_eq!(jti_checks.load(Ordering::SeqCst), 1);

    let list = request(&app, "/api/auth/dash/list-users?limit=1", &old_token).await;
    assert_eq!(list.status(), StatusCode::OK);
    let list = json_body(list).await;
    assert_eq!(list["total"], 1);
    assert_eq!(list["users"][0]["email"], "luna@example.com");
    assert_eq!(list["onlineUsers"], 0);
    assert_eq!(list["activityTrackingEnabled"], false);

    let export = request(&app, "/api/auth/dash/export-users", &old_token).await;
    assert_eq!(export.status(), StatusCode::OK);
    assert_eq!(
        export.headers()[header::CONTENT_TYPE],
        "application/x-ndjson"
    );
    let body = export.into_body().collect().await.unwrap().to_bytes();
    let line: Value = serde_json::from_slice(body.strip_suffix(b"\n").unwrap()).unwrap();
    assert_eq!(line["email"], "luna@example.com");

    server.abort();
}

#[tokio::test]
async fn core_routes_reject_missing_managed_authorization() {
    let (app, _private_key, _jti_checks, _event_queries, server) = fixture().await;
    let response = app
        .oneshot(
            Request::get("/api/auth/dash/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        json_body(response).await,
        json!({"code": "UNAUTHORIZED", "message": "Invalid API key"})
    );
    server.abort();
}

#[tokio::test]
async fn event_queries_use_local_sessions_transform_and_filter_remote_records() {
    let (app, _private_key, _jti_checks, event_queries, server) = fixture().await;
    let cookie = local_cookie(&app).await;

    let response = app
        .clone()
        .oneshot(
            Request::get("/api/auth/events/list?limit=500&offset=-2&eventType=user_signed_in")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["total"], 20);
    assert_eq!(body["limit"], 7);
    assert_eq!(body["offset"], 3);
    assert_eq!(body["events"].as_array().unwrap().len(), 1);
    assert_eq!(body["events"][0]["createdAt"], "2026-08-30T08:00:00.000Z");
    assert_eq!(
        body["events"][0]["location"],
        json!({"ipAddress": "203.0.113.1", "city": null})
    );
    assert!(body["events"][0].get("ipAddress").is_none());
    let query = event_queries.lock().unwrap().pop().unwrap();
    assert!(query.contains("limit=100"), "{query}");
    assert!(query.contains("offset=0"), "{query}");

    let types = app
        .clone()
        .oneshot(
            Request::get("/api/auth/events/types")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(types.status(), StatusCode::OK);
    let types = json_body(types).await;
    assert_eq!(types["user"].as_object().unwrap().len(), 25);
    assert_eq!(types["organization"].as_object().unwrap().len(), 14);
    assert_eq!(types["all"].as_object().unwrap().len(), 39);

    let forbidden = app
        .clone()
        .oneshot(
            Request::get("/api/auth/events/audit-logs?userId=another-user")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json_body(forbidden).await,
        json!({
            "code": "FORBIDDEN",
            "message": "Not allowed to access another user's audit logs"
        })
    );

    server.abort();
}
