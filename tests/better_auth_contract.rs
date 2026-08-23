use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use lucid_auth::{
    Assurance, AuthConfig, AuthService, AuthSession, AuthStore, MemoryStore, NewPasswordUser,
    PasskeyConfig, StoredPasskey,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

async fn application() -> Router {
    let mut config = AuthConfig::new([19_u8; 32]).unwrap();
    config.allow_anonymous = true;
    config.trust_origin("http://localhost").unwrap();
    config.passkeys = Some(PasskeyConfig {
        rp_id: "localhost".into(),
        rp_origin: "http://localhost:5173".into(),
        rp_name: "Example App".into(),
    });
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    service
        .provision_password_user(NewPasswordUser {
            username: "casey".into(),
            name: "Casey".into(),
            email: None,
            password: "password".into(),
            role: "viewer".into(),
        })
        .await
        .unwrap();
    lucid_auth::axum::router(service)
}

async fn recovery_application() -> (Router, Arc<AuthService>, Arc<MemoryStore>) {
    let mut config = AuthConfig::new([29_u8; 32]).unwrap();
    config.trust_origin("http://localhost").unwrap();
    config.passkeys = Some(PasskeyConfig {
        rp_id: "localhost".into(),
        rp_origin: "http://localhost:5173".into(),
        rp_name: "Example App".into(),
    });
    let store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(store.clone(), config));
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let now = Utc::now();
    store
        .save_passkey(StoredPasskey {
            id: Uuid::new_v4(),
            user_id: user.id,
            name: Some("Security key".into()),
            credential_id: "credential".into(),
            credential: json!({}),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    let app = lucid_auth::axum::router(service.clone());
    (app, service, store)
}

async fn persisted_session_cookie(
    service: &AuthService,
    store: &MemoryStore,
    user_id: Uuid,
    assurance: Assurance,
) -> String {
    let token = Uuid::new_v4().to_string();
    let now = Utc::now();
    store
        .create_session(AuthSession {
            id: Uuid::new_v4(),
            user_id,
            token_hash: hex::encode(Sha256::digest(token.as_bytes())),
            actor_user_id: None,
            guest_grant_id: None,
            assurance,
            expires_at: now + Duration::hours(1),
            created_at: now,
            updated_at: now,
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap();
    format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(&token)
    )
}

async fn sign_in(app: &Router, username: &str) -> (String, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/username")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": username, "password": "password" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let body = response_json(response).await;
    (cookie, body)
}

async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn official_username_and_session_contract_round_trip() {
    let app = application().await;
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/username")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"username":"luna","password":"password"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert!(cookie.starts_with("better-auth.session_token="));
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["redirect"], false);
    assert_eq!(body["twoFactorRedirect"], false);
    assert_eq!(body["user"]["username"], "luna");
    assert_eq!(body["user"]["role"], "owner");

    let response = app
        .clone()
        .oneshot(
            Request::get("/api/auth/get-session")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["user"]["name"], "Luna");
    assert_eq!(body["session"]["assurance"], "password");
    assert_eq!(body["session"]["stepUpRequired"], false);

    let response = app
        .oneshot(
            Request::get("/api/auth/passkey/generate-register-options")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("better-auth.better-auth-passkey=")
    );
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["rp"]["id"], "localhost");
    assert_eq!(body["user"]["name"], "luna");
}

#[tokio::test]
async fn official_anonymous_client_contract_creates_a_guest() {
    let response = application()
        .await
        .oneshot(
            Request::post("/api/auth/sign-in/anonymous")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["user"]["role"], "guest");
    assert_eq!(body["user"]["isAnonymous"], true);
}

#[tokio::test]
async fn official_two_factor_client_contract_generates_and_consumes_backup_codes() {
    let (app, service, store) = recovery_application().await;
    let user = store.find_user_by_username("luna").await.unwrap().unwrap();
    let strong_cookie =
        persisted_session_cookie(&service, &store, user.id, Assurance::PasswordAndPasskey).await;

    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/two-factor/generate-backup-codes")
                .header(header::COOKIE, strong_cookie)
                .header(header::ORIGIN, "http://localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"password":"password"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let generated = response_json(response).await;
    assert_eq!(generated["status"], true);
    assert_eq!(generated["backupCodes"].as_array().unwrap().len(), 10);

    let pending_cookie =
        persisted_session_cookie(&service, &store, user.id, Assurance::PasswordPendingPasskey)
            .await;
    let code = generated["backupCodes"][0].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/two-factor/verify-backup-code")
                .header(header::COOKIE, pending_cookie)
                .header(header::ORIGIN, "http://localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "code": code }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(header::SET_COOKIE));
    let verified = response_json(response).await;
    let recovered = service
        .session(verified["token"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.session.assurance, Assurance::Recovery);
    assert_eq!(
        service
            .recovery_code_status(&recovered)
            .await
            .unwrap()
            .remaining,
        9
    );

    let (pending_cookie, _) = sign_in(&app, "luna").await;
    let response = app
        .oneshot(
            Request::post("/api/auth/two-factor/verify-backup-code")
                .header(header::COOKIE, pending_cookie)
                .header(header::ORIGIN, "http://localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "code": code }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response_json(response).await["code"], "INVALID_BACKUP_CODE");
}

#[tokio::test]
async fn official_account_security_contract_manages_sessions() {
    let app = application().await;
    let (current_cookie, _) = sign_in(&app, "luna").await;
    let (other_cookie, _) = sign_in(&app, "luna").await;

    let response = app
        .clone()
        .oneshot(
            Request::get("/api/auth/list-sessions")
                .header(header::COOKIE, &current_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let sessions = response_json(response).await;
    assert_eq!(sessions.as_array().unwrap().len(), 2);
    assert!(Uuid::parse_str(sessions[0]["token"].as_str().unwrap()).is_ok());

    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/revoke-other-sessions")
                .header(header::COOKIE, &current_cookie)
                .header(header::ORIGIN, "http://localhost")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response_json(response).await["status"], true);
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/auth/get-session")
                .header(header::COOKIE, other_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response_json(response).await.is_null());
}

#[tokio::test]
async fn official_account_security_contract_changes_passwords() {
    let app = application().await;
    let (current_cookie, _) = sign_in(&app, "luna").await;
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/change-password")
                .header(header::COOKIE, current_cookie)
                .header(header::ORIGIN, "http://localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "currentPassword": "password",
                        "newPassword": "new-password",
                        "revokeOtherSessions": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(header::SET_COOKIE));
    let changed = response_json(response).await;
    assert_eq!(changed["user"]["username"], "luna");
    assert!(changed["token"].as_str().is_some());

    let response = app
        .oneshot(
            Request::post("/api/auth/sign-in/username")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": "luna", "password": "new-password" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
