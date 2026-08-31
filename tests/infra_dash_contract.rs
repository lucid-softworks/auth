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
    AuthConfig, AuthService, DashAdapterWhere, DashManagedDirectorySync, DashOptions, DashPlugin,
    DatabaseScimStore, InfraConnectionOptions, MemoryOrganizationStore, MemorySsoStore,
    MemoryStore, MemoryTwoFactorStore, NewPasswordUser, NewSsoProvider, OrganizationPlugin,
    OrganizationPluginConfig, SCIM_MEDIA_TYPE, SCIM_USER_SCHEMA, ScimManagedConnectionOptions,
    ScimOptions, ScimPlugin, SsoOptions, SsoPlugin, SsoStore, TwoFactorConfig, TwoFactorPlugin,
    run_database_transaction,
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
    tracked_events: Arc<Mutex<Vec<Value>>>,
    invitation_requests: Arc<Mutex<Vec<Value>>>,
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

async fn track_event(State(api): State<ManagedApi>, Json(event): Json<Value>) -> StatusCode {
    api.tracked_events.lock().unwrap().push(event);
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn verify_invitation(State(api): State<ManagedApi>, Json(body): Json<Value>) -> Json<Value> {
    api.invitation_requests
        .lock()
        .unwrap()
        .push(json!({"operation": "verify", "body": body}));
    if body["token"] == "social-no-session" {
        Json(json!({
            "email": "luna@example.com",
            "name": "Luna",
            "status": "pending",
            "expiresAt": "2030-01-01T00:00:00Z",
            "redirectUrl": "http://localhost/welcome",
            "authMode": "create_no_session"
        }))
    } else {
        let redirect_url = if body["token"] == "evil-redirect" {
            "https://evil.example/steal"
        } else {
            "http://localhost/welcome"
        };
        Json(json!({
            "email": "nova@example.com",
            "name": "Nova",
            "status": "pending",
            "expiresAt": "2030-01-01T00:00:00Z",
            "redirectUrl": redirect_url,
            "authMode": null
        }))
    }
}

async fn mark_invitation_accepted(
    State(api): State<ManagedApi>,
    Json(body): Json<Value>,
) -> Json<Value> {
    api.invitation_requests
        .lock()
        .unwrap()
        .push(json!({"operation": "mark-accepted", "body": body}));
    Json(json!({"success": true}))
}

async fn fixture() -> (
    Router,
    Jwk,
    Arc<AtomicUsize>,
    Arc<Mutex<Vec<String>>>,
    Arc<Mutex<Vec<Value>>>,
    Arc<Mutex<Vec<Value>>>,
    Arc<MemorySsoStore>,
    Arc<MemoryStore>,
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
    let tracked_events = Arc::new(Mutex::new(Vec::new()));
    let invitation_requests = Arc::new(Mutex::new(Vec::new()));
    let managed = Router::new()
        .route("/api/auth/jwks", get(jwks))
        .route("/api/auth/check-jti", post(check_jti))
        .route("/events/user", get(user_events))
        .route("/events/track", post(track_event))
        .route("/api/internal/invitations/verify", post(verify_invitation))
        .route(
            "/api/internal/invitations/mark-accepted",
            post(mark_invitation_accepted),
        )
        .with_state(ManagedApi {
            public_key: serde_json::to_value(public_key).unwrap(),
            jti_checks: jti_checks.clone(),
            event_queries: event_queries.clone(),
            tracked_events: tracked_events.clone(),
            invitation_requests: invitation_requests.clone(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, managed).await.unwrap() });

    let mut config = AuthConfig::new([b'D'; 32]).unwrap();
    let auth_store = Arc::new(MemoryStore::default());
    config.set_base_url("http://localhost").unwrap();
    config.email_and_password.enabled = true;
    let mut organization_config = OrganizationPluginConfig::default();
    organization_config.teams.enabled = true;
    organization_config.teams.default_team_enabled = false;
    config
        .add_plugin(OrganizationPlugin::with_config(
            Arc::new(MemoryOrganizationStore::default()),
            organization_config,
        ))
        .unwrap();
    config
        .add_plugin(TwoFactorPlugin::new(
            Arc::new(MemoryTwoFactorStore::default()),
            TwoFactorConfig::default(),
        ))
        .unwrap();
    let sso_store = Arc::new(MemorySsoStore::new());
    config
        .add_plugin(SsoPlugin::with_store(
            SsoOptions {
                domain_verification: true,
                ..SsoOptions::default()
            },
            sso_store.clone(),
        ))
        .unwrap();
    config
        .add_plugin(
            ScimPlugin::new(
                ScimOptions {
                    managed_connections: Some(ScimManagedConnectionOptions::new(
                        "dash-managed-scim-secret-at-least-32-bytes",
                    )),
                    ..ScimOptions::default()
                },
                Arc::new(DatabaseScimStore::new(auth_store.clone())),
            )
            .unwrap(),
        )
        .unwrap();
    config
        .add_plugin(DashPlugin::new(DashOptions {
            connection: InfraConnectionOptions {
                api_url: Some(format!("http://{address}")),
                api_key: Some("managed-contract-key".into()),
                ..InfraConnectionOptions::default()
            },
            managed_directory_sync: DashManagedDirectorySync {
                enabled: true,
                ..DashManagedDirectorySync::default()
            },
            ..DashOptions::default()
        }))
        .unwrap();
    let service = Arc::new(AuthService::new(auth_store.clone(), config));
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
        tracked_events,
        invitation_requests,
        sso_store,
        auth_store,
        server,
    )
}

fn token(private_key: &Jwk, age_seconds: i64) -> String {
    token_with(private_key, age_seconds, json!({}))
}

fn token_with(private_key: &Jwk, age_seconds: i64, additional: Value) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut claims = json!({
        "iat": now - age_seconds,
        "exp": now + 3_600,
        "jti": "dash-contract-jti",
        "apiKeyHash": hex::encode(Sha256::digest(b"managed-contract-key")),
    });
    claims
        .as_object_mut()
        .unwrap()
        .extend(additional.as_object().unwrap().clone());
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

async fn post_json(app: &Router, uri: &str, token: &str, body: Value) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::post(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

async fn generic_count(
    store: Arc<MemoryStore>,
    model: &str,
    where_clause: Vec<DashAdapterWhere>,
) -> u64 {
    let model = model.to_owned();
    run_database_transaction(store.as_ref(), move |database| {
        Box::pin(async move { database.count_records(&model, &where_clause).await })
    })
    .await
    .unwrap()
}

async fn wait_for_events(events: &Arc<Mutex<Vec<Value>>>, expected: usize) -> Vec<Value> {
    for _ in 0..100 {
        let snapshot = events.lock().unwrap().clone();
        if snapshot.len() >= expected {
            return snapshot;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {expected} Dash events");
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
    let (
        app,
        private_key,
        jti_checks,
        _event_queries,
        _tracked_events,
        _invites,
        _sso,
        _store,
        server,
    ) = fixture().await;
    let old_token = token(&private_key, 60);

    let config = request(&app, "/api/auth/dash/config", &old_token).await;
    assert_eq!(config.status(), StatusCode::OK);
    let config = json_body(config).await;
    assert_eq!(config["version"], "1.7.2");
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
    let (
        app,
        _private_key,
        _jti_checks,
        _event_queries,
        _tracked_events,
        _invites,
        _sso,
        _store,
        server,
    ) = fixture().await;
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
    let (
        app,
        _private_key,
        _jti_checks,
        event_queries,
        _tracked_events,
        _invites,
        _sso,
        _store,
        server,
    ) = fixture().await;
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

#[tokio::test]
async fn auth_hooks_project_exact_events_once_and_ignore_remote_500s() {
    let (
        app,
        _private_key,
        _jti_checks,
        _event_queries,
        tracked_events,
        _invites,
        _sso,
        _store,
        server,
    ) = fixture().await;
    assert!(tracked_events.lock().unwrap().is_empty());

    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/email")
                .header(header::CONTENT_TYPE, "application/json")
                .header("cf-connecting-ip", "203.0.113.44")
                .header("cf-ipcountry", "GB")
                .body(Body::from(
                    json!({"email": "luna@example.com", "password": "password"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let events = wait_for_events(&tracked_events, 2).await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["eventType"], "user_signed_in");
    assert_eq!(events[0]["eventDisplayName"], "Signed in via email");
    assert_eq!(events[0]["eventData"]["loginMethod"], "email");
    assert_eq!(events[0]["ipAddress"], "203.0.113.44");
    assert_eq!(events[0]["countryCode"], "GB");
    assert_eq!(events[1]["eventType"], "session_created");
    assert!(
        !events
            .iter()
            .any(|event| event.to_string().contains("password"))
    );

    let failed = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/email")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"email": "luna@example.com", "password": "wrong-password"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(failed.status(), StatusCode::UNAUTHORIZED);
    let events = wait_for_events(&tracked_events, 3).await;
    assert_eq!(events.len(), 3);
    assert_eq!(events[2]["eventType"], "user_sign_in_failed");
    assert_eq!(events[2]["eventData"]["userEmail"], "luna@example.com");
    assert_eq!(events[2]["eventData"]["loginMethod"], "email");
    server.abort();
}

#[tokio::test]
async fn organization_hooks_project_in_order_and_keep_remote_failures_non_fatal() {
    let (
        app,
        _private_key,
        _jti_checks,
        _event_queries,
        tracked_events,
        _invites,
        _sso,
        _store,
        server,
    ) = fixture().await;
    let cookie = local_cookie(&app).await;
    wait_for_events(&tracked_events, 2).await;
    tracked_events.lock().unwrap().clear();

    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/organization/create")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .header(header::ORIGIN, "http://localhost")
                .header(header::HOST, "localhost")
                .body(Body::from(
                    json!({"name": "Acme", "slug": "acme"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let events = wait_for_events(&tracked_events, 2).await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["eventType"], "organization_member_added");
    assert_eq!(events[0]["eventData"]["organizationSlug"], "acme");
    assert_eq!(events[0]["eventData"]["triggerContext"], "organization");
    assert_eq!(events[1]["eventType"], "organization_created");
    assert!(
        events
            .iter()
            .all(|event| event.get("inviteeEmail").is_none())
    );
    server.abort();
}

#[tokio::test]
async fn managed_organization_team_and_two_factor_routes_use_native_stores() {
    let (
        app,
        private_key,
        _jti_checks,
        _event_queries,
        _tracked_events,
        _invites,
        _sso,
        _store,
        server,
    ) = fixture().await;
    let base_token = token(&private_key, 0);
    let users = request(&app, "/api/auth/dash/list-users", &base_token).await;
    assert_eq!(users.status(), StatusCode::OK);
    let user_id = json_body(users).await["users"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let user_token = token_with(
        &private_key,
        0,
        json!({"userId": user_id.clone(), "skipDefaultTeam": true}),
    );
    let created = post_json(
        &app,
        "/api/auth/dash/organization/create",
        &user_token,
        json!({"name": "Managed Acme", "slug": "managed-acme"}),
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let created = json_body(created).await;
    let organization_id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(created["members"][0]["role"], "owner");

    let organizations = request(&app, "/api/auth/dash/list-organizations", &base_token).await;
    assert_eq!(organizations.status(), StatusCode::OK);
    let organizations = json_body(organizations).await;
    assert_eq!(organizations["total"], 1);
    assert_eq!(organizations["organizations"][0]["memberCount"], 1);

    let members = request(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/members"),
        &base_token,
    )
    .await;
    assert_eq!(members.status(), StatusCode::OK);
    let members = json_body(members).await;
    assert_eq!(members[0]["user"]["email"], "luna@example.com");
    let member_id = members[0]["id"].as_str().unwrap().to_owned();

    let organization_token = token_with(
        &private_key,
        0,
        json!({"organizationId": organization_id.clone()}),
    );
    let mismatch = post_json(
        &app,
        "/api/auth/dash/organization/delete",
        &organization_token,
        json!({"organizationId": "another-organization"}),
    )
    .await;
    assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
    let team = post_json(
        &app,
        "/api/auth/dash/organization/create-team",
        &organization_token,
        json!({"name": "Platform"}),
    )
    .await;
    assert_eq!(team.status(), StatusCode::OK);
    let team_id = json_body(team).await["id"].as_str().unwrap().to_owned();
    let added = post_json(
        &app,
        "/api/auth/dash/organization/add-team-member",
        &organization_token,
        json!({"teamId": team_id.clone(), "userId": user_id.clone()}),
    )
    .await;
    assert_eq!(added.status(), StatusCode::OK);
    let team_members = request(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/teams/{team_id}/members"),
        &base_token,
    )
    .await;
    assert_eq!(team_members.status(), StatusCode::OK);
    assert_eq!(json_body(team_members).await[0]["user"]["id"], user_id);

    let updated_member = post_json(
        &app,
        "/api/auth/dash/organization/update-member-role",
        &organization_token,
        json!({"memberId": member_id.clone(), "role": "member"}),
    )
    .await;
    assert_eq!(updated_member.status(), StatusCode::OK);
    assert_eq!(json_body(updated_member).await["role"], "member");
    let removed_member = post_json(
        &app,
        "/api/auth/dash/organization/remove-member",
        &organization_token,
        json!({"memberId": member_id}),
    )
    .await;
    assert_eq!(removed_member.status(), StatusCode::OK);
    let team_members = request(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/teams/{team_id}/members"),
        &base_token,
    )
    .await;
    assert_eq!(json_body(team_members).await, json!([]));

    let enabled = post_json(
        &app,
        "/api/auth/dash/enable-two-factor",
        &user_token,
        json!({}),
    )
    .await;
    assert_eq!(enabled.status(), StatusCode::OK);
    let enabled = json_body(enabled).await;
    assert_eq!(enabled["success"], true);
    assert_eq!(enabled["secret"].as_str().unwrap().len(), 32);
    assert_eq!(enabled["backupCodes"].as_array().unwrap().len(), 10);

    let uri = post_json(
        &app,
        "/api/auth/dash/view-two-factor-totp-uri",
        &user_token,
        json!({}),
    )
    .await;
    assert_eq!(uri.status(), StatusCode::OK);
    assert!(
        json_body(uri).await["totpURI"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/")
    );
    let forbidden = post_json(
        &app,
        "/api/auth/dash/view-backup-codes",
        &user_token,
        json!({}),
    )
    .await;
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    let generated = post_json(
        &app,
        "/api/auth/dash/generate-backup-codes",
        &user_token,
        json!({}),
    )
    .await;
    assert_eq!(generated.status(), StatusCode::OK);
    assert_eq!(
        json_body(generated).await["backupCodes"]
            .as_array()
            .unwrap()
            .len(),
        10
    );
    let disabled = post_json(
        &app,
        "/api/auth/dash/disable-two-factor",
        &user_token,
        json!({}),
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::OK);
    assert_eq!(json_body(disabled).await, json!({"success": true}));
    server.abort();
}

#[tokio::test]
async fn dash_sso_listing_is_tenant_bound_and_never_returns_secrets() {
    let (app, private_key, _jti, _queries, _events, _invites, sso, _store, server) =
        fixture().await;
    let base_token = token(&private_key, 0);
    let users = request(&app, "/api/auth/dash/list-users", &base_token).await;
    let user_id = json_body(users).await["users"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let user_token = token_with(
        &private_key,
        0,
        json!({"userId": user_id.clone(), "skipDefaultTeam": true}),
    );
    let created = post_json(
        &app,
        "/api/auth/dash/organization/create",
        &user_token,
        json!({"name": "SSO Acme", "slug": "sso-acme"}),
    )
    .await;
    let organization_id = json_body(created).await["id"].as_str().unwrap().to_owned();
    sso.create(NewSsoProvider {
        id: "dash-sso-row".into(),
        issuer: "https://issuer.example.com".into(),
        oidc_config: Some(json!({
            "clientId": "managed-client-1234",
            "clientSecret": "never-return-this",
            "authorizationEndpoint": "https://issuer.example.com/authorize",
            "tokenEndpoint": "https://issuer.example.com/token",
            "jwksEndpoint": "https://issuer.example.com/jwks"
        })),
        saml_config: None,
        user_id: user_id.clone(),
        provider_id: "managed-oidc".into(),
        organization_id: Some(organization_id.clone()),
        domain: "example.com".into(),
        domain_verified: Some(true),
        additional_fields: serde_json::Map::new(),
    })
    .await
    .unwrap();
    sso.create(NewSsoProvider {
        id: "foreign-sso-row".into(),
        issuer: "https://foreign.example.com".into(),
        oidc_config: None,
        saml_config: None,
        user_id: user_id.clone(),
        provider_id: "foreign".into(),
        organization_id: Some("foreign-organization".into()),
        domain: "foreign.example.com".into(),
        domain_verified: Some(true),
        additional_fields: serde_json::Map::new(),
    })
    .await
    .unwrap();
    let organization_token = token_with(
        &private_key,
        0,
        json!({"organizationId": organization_id.clone()}),
    );

    let created_provider = post_json(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/sso-provider/create"),
        &organization_token,
        json!({
            "providerId": "dash-created",
            "domain": "created.example.com",
            "protocol": "OIDC",
            "userId": user_id,
            "oidcConfig": {
                "clientId": "created-client",
                "clientSecret": "created-secret",
                "issuer": "https://created.example.com",
                "authorizationEndpoint": "https://created.example.com/authorize",
                "tokenEndpoint": "https://created.example.com/token",
                "jwksEndpoint": "https://created.example.com/jwks"
            }
        }),
    )
    .await;
    assert_eq!(created_provider.status(), StatusCode::OK);
    let created_provider = json_body(created_provider).await;
    assert_eq!(created_provider["provider"]["providerId"], "dash-created");
    assert_eq!(
        created_provider["domainVerification"]["verificationToken"]
            .as_str()
            .unwrap()
            .len(),
        24
    );
    assert!(!created_provider.to_string().contains("created-secret"));

    let updated_provider = post_json(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/sso-provider/update"),
        &organization_token,
        json!({
            "providerId": "dash-created",
            "domain": "updated.example.com",
            "protocol": "OIDC",
            "oidcConfig": {
                "clientId": "updated-client",
                "issuer": "https://created.example.com",
                "authorizationEndpoint": "https://created.example.com/authorize",
                "tokenEndpoint": "https://created.example.com/token",
                "jwksEndpoint": "https://created.example.com/jwks"
            }
        }),
    )
    .await;
    assert_eq!(updated_provider.status(), StatusCode::OK);
    let stored_created = sso
        .find_by_provider_id("dash-created")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_created.domain, "updated.example.com");
    assert_eq!(
        stored_created.oidc_config.as_ref().unwrap()["clientSecret"],
        "created-secret"
    );
    let deleted_created = post_json(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/sso-provider/delete"),
        &organization_token,
        json!({"providerId": "dash-created"}),
    )
    .await;
    assert_eq!(deleted_created.status(), StatusCode::OK);

    let listed = request(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/sso-providers"),
        &organization_token,
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = json_body(listed).await;
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["providerId"], "managed-oidc");
    assert_eq!(listed[0]["oidcConfig"]["clientIdLastFour"], "****1234");
    assert!(!listed.to_string().contains("never-return-this"));

    let wrong_token = token_with(
        &private_key,
        0,
        json!({"organizationId": "foreign-organization"}),
    );
    let forbidden = request(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/sso-providers"),
        &wrong_token,
    )
    .await;
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let unmarked = post_json(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/sso-provider/mark-domain-verified"),
        &organization_token,
        json!({"providerId": "managed-oidc", "verified": false}),
    )
    .await;
    assert_eq!(unmarked.status(), StatusCode::OK);
    assert_eq!(json_body(unmarked).await["domainVerified"], false);
    assert_eq!(
        sso.find_by_provider_id("managed-oidc")
            .await
            .unwrap()
            .unwrap()
            .domain_verified,
        Some(false)
    );

    let requested = post_json(
        &app,
        &format!(
            "/api/auth/dash/organization/{organization_id}/sso-provider/request-verification-token"
        ),
        &organization_token,
        json!({"providerId": "managed-oidc"}),
    )
    .await;
    assert_eq!(requested.status(), StatusCode::OK);
    let requested = json_body(requested).await;
    assert_eq!(
        requested["txtRecordName"],
        "_better-auth-token-managed-oidc"
    );
    assert_eq!(requested["verificationToken"].as_str().unwrap().len(), 24);
    let requested_again = post_json(
        &app,
        &format!(
            "/api/auth/dash/organization/{organization_id}/sso-provider/request-verification-token"
        ),
        &organization_token,
        json!({"providerId": "managed-oidc"}),
    )
    .await;
    assert_eq!(
        json_body(requested_again).await["verificationToken"],
        requested["verificationToken"]
    );

    let deleted = post_json(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/sso-provider/delete"),
        &organization_token,
        json!({"providerId": "managed-oidc"}),
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::OK);
    assert_eq!(json_body(deleted).await["success"], true);
    assert!(
        sso.find_by_provider_id("managed-oidc")
            .await
            .unwrap()
            .is_none()
    );
    server.abort();
}

#[tokio::test]
async fn managed_directory_routes_bind_scim_and_protect_one_time_credentials() {
    let (app, private_key, _jti, _queries, _events, _invites, _sso, store, server) =
        fixture().await;
    let base_token = token(&private_key, 0);
    let users = request(&app, "/api/auth/dash/list-users", &base_token).await;
    let user_id = json_body(users).await["users"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let user_token = token_with(
        &private_key,
        0,
        json!({"userId": user_id, "skipDefaultTeam": true}),
    );
    let created_organization = post_json(
        &app,
        "/api/auth/dash/organization/create",
        &user_token,
        json!({"name": "Directory Acme", "slug": "directory-acme"}),
    )
    .await;
    let organization_id = json_body(created_organization).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let organization_token =
        token_with(&private_key, 0, json!({"organizationId": organization_id}));
    let sso_provider = post_json(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/sso-provider/create"),
        &organization_token,
        json!({
            "providerId": "directory-login",
            "domain": "directory.example.com",
            "protocol": "OIDC",
            "userId": user_id,
            "oidcConfig": {
                "clientId": "directory-client",
                "clientSecret": "directory-secret",
                "issuer": "https://directory.example.com",
                "authorizationEndpoint": "https://directory.example.com/authorize",
                "tokenEndpoint": "https://directory.example.com/token",
                "jwksEndpoint": "https://directory.example.com/jwks"
            }
        }),
    )
    .await;
    assert_eq!(sso_provider.status(), StatusCode::OK);
    let setup_token = token_with(
        &private_key,
        0,
        json!({
            "purpose": "directory-sync-management",
            "organizationId": organization_id,
            "actorId": "setup-actor",
            "setupOperationId": "setup-operation-0001"
        }),
    );
    let created = post_json(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/directories"),
        &setup_token,
        json!({
            "providerId": "entra",
            "pairing": {
                "ssoProviderId": "directory-login",
                "protocol": "oidc",
                "externalIdSource": {"kind": "subject"}
            }
        }),
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    assert_eq!(
        created.headers()[header::CACHE_CONTROL],
        "no-store, max-age=0"
    );
    assert_eq!(created.headers()[header::PRAGMA], "no-cache");
    let created = json_body(created).await;
    let connection_id = created["connectionId"].as_str().unwrap().to_owned();
    assert!(created["credential"]["credentialId"].as_str().is_some());
    let mut first_token = created["scimToken"].as_str().unwrap().to_owned();
    assert!(connection_id.starts_with("ba_scim_connection_"));
    assert!(first_token.starts_with("ba_scim_credential_"));
    assert_eq!(created["credentials"].as_array().unwrap().len(), 1);
    assert_eq!(created["pairingEnforced"], true);
    assert_eq!(created["pairing"]["ssoProviderId"], "directory-login");

    let provisioned = app
        .clone()
        .oneshot(
            Request::post("/api/auth/scim/v2/Users")
                .header(header::AUTHORIZATION, format!("Bearer {first_token}"))
                .header(header::CONTENT_TYPE, SCIM_MEDIA_TYPE)
                .body(Body::from(
                    json!({
                        "schemas": [SCIM_USER_SCHEMA],
                        "externalId": "directory-subject",
                        "userName": "provisioned@example.com",
                        "name": {"formatted": "Provisioned User"},
                        "emails": [{"value": "provisioned@example.com", "type": "work", "primary": true}],
                        "active": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(provisioned.status(), StatusCode::CREATED);
    let provisioned_id = json_body(provisioned).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let organization_filter = || {
        vec![DashAdapterWhere {
            field: "organizationId".into(),
            value: json!(organization_id),
            operator: Default::default(),
            connector: None,
        }]
    };
    assert_eq!(
        generic_count(store.clone(), "member", organization_filter()).await,
        1
    );
    assert_eq!(
        generic_count(
            store.clone(),
            "directorySyncMembershipProvenance",
            organization_filter(),
        )
        .await,
        1
    );
    let deprovisioned = app
        .clone()
        .oneshot(
            Request::delete(format!("/api/auth/scim/v2/Users/{provisioned_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {first_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deprovisioned.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        generic_count(store.clone(), "member", organization_filter()).await,
        0
    );
    assert_eq!(
        generic_count(
            store.clone(),
            "directorySyncMembershipProvenance",
            organization_filter(),
        )
        .await,
        0
    );

    let recovered = post_json(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/directories"),
        &setup_token,
        json!({
            "providerId": "entra",
            "pairing": {
                "ssoProviderId": "directory-login",
                "protocol": "oidc",
                "externalIdSource": {"kind": "subject"}
            }
        }),
    )
    .await;
    assert_eq!(recovered.status(), StatusCode::OK);
    let recovered = json_body(recovered).await;
    assert_eq!(recovered["connectionId"], connection_id);
    assert_ne!(recovered["scimToken"], first_token);
    first_token = recovered["scimToken"].as_str().unwrap().to_owned();
    let credential_id = recovered["credential"]["credentialId"]
        .as_str()
        .unwrap()
        .to_owned();

    let guarded_delete = post_json(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/sso-provider/delete"),
        &organization_token,
        json!({"providerId": "directory-login"}),
    )
    .await;
    assert_eq!(guarded_delete.status(), StatusCode::CONFLICT);

    let setup_forbidden = request(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/directories"),
        &setup_token,
    )
    .await;
    assert_eq!(setup_forbidden.status(), StatusCode::FORBIDDEN);

    let management_token = token_with(
        &private_key,
        0,
        json!({
            "purpose": "directory-sync-management",
            "organizationId": organization_id,
            "actorId": "management-actor"
        }),
    );
    let listed = request(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/directories"),
        &management_token,
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = json_body(listed).await;
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["providerId"], "entra");
    assert!(!listed.to_string().contains(&first_token));

    let duplicate = post_json(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/directories"),
        &management_token,
        json!({"providerId": "okta"}),
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);

    let rotated = post_json(
        &app,
        &format!(
            "/api/auth/dash/organization/{organization_id}/directories/entra/credentials/rotate"
        ),
        &management_token,
        json!({"scopes": ["scim.users.read"]}),
    )
    .await;
    assert_eq!(rotated.status(), StatusCode::OK);
    assert_eq!(
        rotated.headers()[header::CACHE_CONTROL],
        "no-store, max-age=0"
    );
    let rotated = json_body(rotated).await;
    assert_ne!(rotated["scimToken"], first_token);
    assert_eq!(rotated["credential"]["scopes"], json!(["scim.users.read"]));

    let revoked = post_json(
        &app,
        &format!(
            "/api/auth/dash/organization/{organization_id}/directories/entra/credentials/{credential_id}/revoke"
        ),
        &management_token,
        json!({}),
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::OK);
    let revoked = json_body(revoked).await;
    assert!(
        revoked["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| {
                value["credentialId"] == credential_id && value["status"] == "revoked"
            })
    );

    let events = request(
        &app,
        &format!(
            "/api/auth/dash/organization/{organization_id}/directories/entra/events?limit=2&sortDirection=asc"
        ),
        &management_token,
    )
    .await;
    assert_eq!(events.status(), StatusCode::OK);
    let events = json_body(events).await;
    assert_eq!(events["limit"], 2);
    assert_eq!(events["offset"], 0);
    assert_eq!(events["events"].as_array().unwrap().len(), 2);
    assert_eq!(events["events"][0]["type"], "connection.created");

    let decommissioned = post_json(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/directories/entra/decommission"),
        &management_token,
        json!({}),
    )
    .await;
    assert_eq!(decommissioned.status(), StatusCode::OK);
    assert_eq!(json_body(decommissioned).await["status"], "decommissioned");
    let unpaired = post_json(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/directories/entra/unpair"),
        &management_token,
        json!({}),
    )
    .await;
    assert_eq!(unpaired.status(), StatusCode::OK);
    assert_eq!(json_body(unpaired).await["pairingEnforced"], false);
    let deleted_sso = post_json(
        &app,
        &format!("/api/auth/dash/organization/{organization_id}/sso-provider/delete"),
        &organization_token,
        json!({"providerId": "directory-login"}),
    )
    .await;
    assert_eq!(deleted_sso.status(), StatusCode::OK);
    server.abort();
}

#[tokio::test]
async fn public_invitation_acceptance_uses_managed_egress_and_mints_local_session() {
    let (
        app,
        _private_key,
        _jti_checks,
        _event_queries,
        _tracked_events,
        invitation_requests,
        _sso,
        _store,
        server,
    ) = fixture().await;
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/auth/dash/accept-invitation?token=managed-invite")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers()[header::LOCATION],
        "http://localhost/welcome"
    );
    assert!(response.headers().contains_key(header::SET_COOKIE));

    let requests = invitation_requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0],
        json!({
            "operation": "verify",
            "body": {"token": "managed-invite"}
        })
    );
    assert_eq!(requests[1]["operation"], "mark-accepted");
    assert_eq!(requests[1]["body"]["token"], "managed-invite");
    assert!(requests[1]["body"]["userId"].as_str().is_some());

    let untrusted = app
        .clone()
        .oneshot(
            Request::get("/api/auth/dash/accept-invitation?token=evil-redirect")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(untrusted.status(), StatusCode::FOUND);
    assert_eq!(untrusted.headers()[header::LOCATION], "http://localhost");
    server.abort();
}

#[tokio::test]
async fn social_create_no_session_invitation_revokes_the_local_session() {
    let (
        app,
        _private_key,
        _jti_checks,
        _event_queries,
        _tracked_events,
        _invites,
        _sso,
        _store,
        server,
    ) = fixture().await;
    let cookie = local_cookie(&app).await;
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/auth/dash/complete-invitation-social?token=social-no-session")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );

    let session = app
        .clone()
        .oneshot(
            Request::get("/api/auth/get-session")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session.status(), StatusCode::OK);
    assert_eq!(json_body(session).await, Value::Null);
    server.abort();
}
