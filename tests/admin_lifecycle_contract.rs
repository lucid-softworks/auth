use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{AuthConfig, AuthService, MemoryStore, NewPasswordUser};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

async fn application() -> Router {
    let service = Arc::new(AuthService::new(
        Arc::new(MemoryStore::default()),
        AuthConfig::new([43_u8; 32]).unwrap(),
    ));
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

async fn request_json(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, value)
}

async fn sign_in(app: &Router, username: &str, password: &str) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/username")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": username, "password": password }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .unwrap_or_default()
        .to_owned();
    (status, cookie)
}

#[tokio::test]
async fn official_admin_client_contract_manages_an_account_lifecycle() {
    let app = application().await;
    let (status, owner_cookie) = sign_in(&app, "luna", "password").await;
    assert_eq!(status, StatusCode::OK);

    let (status, created) = request_json(
        &app,
        Request::post("/api/auth/admin/create-user")
            .header(header::COOKIE, &owner_cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "email": "casey@example.com",
                    "password": "initial-password",
                    "name": "Casey",
                    "role": "member",
                    "data": { "username": "casey" }
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created["user"]["username"], "casey");
    assert_eq!(created["user"]["role"], "member");
    let user_id = created["user"]["id"].as_str().unwrap();
    assert_eq!(
        sign_in(&app, "casey", "initial-password").await.0,
        StatusCode::OK
    );

    let (status, reset) = request_json(
        &app,
        Request::post("/api/auth/admin/set-user-password")
            .header(header::COOKIE, &owner_cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "userId": user_id, "newPassword": "replacement-password" }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reset["status"], true);
    assert_eq!(
        sign_in(&app, "casey", "initial-password").await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        sign_in(&app, "casey", "replacement-password").await.0,
        StatusCode::OK
    );

    let (status, removed) = request_json(
        &app,
        Request::post("/api/auth/admin/remove-user")
            .header(header::COOKIE, owner_cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "userId": user_id }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(removed["success"], true);
    assert_eq!(
        sign_in(&app, "casey", "replacement-password").await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn account_lifecycle_rejects_duplicates_and_owner_self_removal() {
    let app = application().await;
    let (_, owner_cookie) = sign_in(&app, "luna", "password").await;
    let (_, users) = request_json(
        &app,
        Request::get("/api/auth/admin/list-users")
            .header(header::COOKIE, &owner_cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let owner_id = users["users"][0]["id"].as_str().unwrap();

    let (status, removed) = request_json(
        &app,
        Request::post("/api/auth/admin/remove-user")
            .header(header::COOKIE, &owner_cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "userId": owner_id }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(removed["code"], "FORBIDDEN");

    let create = || {
        Request::post("/api/auth/admin/create-user")
            .header(header::COOKIE, &owner_cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "email": "luna@users.localhost",
                    "password": "another-password",
                    "name": "Duplicate",
                    "data": { "username": "duplicate" }
                })
                .to_string(),
            ))
            .unwrap()
    };
    let (status, duplicate) = request_json(&app, create()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(duplicate["code"], "USER_ALREADY_EXISTS");
}
