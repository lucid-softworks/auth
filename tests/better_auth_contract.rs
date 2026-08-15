use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{AuthConfig, AuthService, MemoryStore, NewPasswordUser, PasskeyConfig};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

async fn application() -> Router {
    let mut config = AuthConfig::new([19_u8; 32]).unwrap();
    config.allow_anonymous = true;
    config.passkeys = Some(PasskeyConfig {
        rp_id: "localhost".into(),
        rp_origin: "http://localhost:5173".into(),
        rp_name: "Haven".into(),
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
    lucid_auth::axum::router(service)
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
