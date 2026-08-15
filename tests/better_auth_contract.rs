use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{AuthConfig, AuthService, MemoryStore, NewPasswordUser, PasskeyConfig};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

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
async fn official_account_security_contract_changes_passwords_and_manages_sessions() {
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

    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/change-password")
                .header(header::COOKIE, current_cookie)
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

#[tokio::test]
async fn official_admin_contract_supports_roles_and_impersonation() {
    let app = application().await;
    let (owner_cookie, owner_body) = sign_in(&app, "luna").await;
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/auth/admin/list-users?limit=20&offset=0")
                .header(header::COOKIE, &owner_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let users = response_json(response).await;
    assert_eq!(users["total"], 2);
    let casey = users["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|user| user["username"] == "casey")
        .unwrap();
    let casey_id = casey["id"].as_str().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/admin/set-role")
                .header(header::COOKIE, &owner_cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "userId": casey_id, "role": "member" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response_json(response).await["user"]["role"], "member");

    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/admin/impersonate-user")
                .header(header::COOKIE, &owner_cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "userId": casey_id }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let impersonated_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let impersonated = response_json(response).await;
    assert_eq!(impersonated["user"]["username"], "casey");
    assert_eq!(
        impersonated["session"]["impersonatedBy"],
        owner_body["user"]["id"]
    );

    let response = app
        .oneshot(
            Request::post("/api/auth/admin/stop-impersonating")
                .header(header::COOKIE, impersonated_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response_json(response).await["user"]["username"], "luna");
}

#[tokio::test]
async fn guest_grant_contract_issues_and_redeems_a_scoped_session() {
    let app = application().await;
    let (owner_cookie, _) = sign_in(&app, "luna").await;
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/guest-grants")
                .header(header::COOKIE, owner_cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "label": "Dog sitter",
                        "permissions": ["devices:read"],
                        "resourceScopes": ["room:kitchen"],
                        "expiresAt": (chrono::Utc::now() + chrono::Duration::hours(1)),
                        "maxUses": 1
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let issued = response_json(response).await;
    assert_eq!(issued["grant"]["permissions"][0], "devices:read");

    let response = app
        .oneshot(
            Request::post("/api/auth/sign-in/guest-grant")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "token": issued["token"] }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let guest = response_json(response).await;
    assert_eq!(guest["user"]["role"], "guest");
    assert_eq!(guest["session"]["guestGrantId"], issued["grant"]["id"]);
}
