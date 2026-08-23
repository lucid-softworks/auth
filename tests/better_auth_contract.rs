use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, MemoryStore, NewPasswordUser, PasskeyConfig, PasskeyPlugin,
    UsernamePlugin,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

async fn application() -> Router {
    let mut config = AuthConfig::new([19_u8; 32]).unwrap();
    config.allow_anonymous = true;
    config.trust_origin("http://localhost").unwrap();
    config.add_plugin(UsernamePlugin::default()).unwrap();
    config
        .add_plugin(PasskeyPlugin::new(PasskeyConfig {
            rp_id: Some("localhost".into()),
            rp_name: Some("Example App".into()),
            origins: Some(vec!["http://localhost:5173".into()]),
            ..PasskeyConfig::default()
        }))
        .unwrap();
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
    assert!(body.get("twoFactorRedirect").is_none());
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
async fn two_factor_routes_are_absent_without_the_plugin() {
    let app = application().await;
    let (_, signed_in) = sign_in(&app, "luna").await;
    assert!(signed_in["user"].get("twoFactorEnabled").is_none());
    for path in [
        "/two-factor/enable",
        "/two-factor/disable",
        "/two-factor/get-totp-uri",
        "/two-factor/verify-totp",
        "/two-factor/send-otp",
        "/two-factor/verify-otp",
        "/two-factor/generate-backup-codes",
        "/two-factor/verify-backup-code",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::post(format!("/api/auth{path}"))
                    .header(header::ORIGIN, "http://localhost")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
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
