use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AdminConfig, AdminPlugin, AdminRole, AuthConfig, AuthService, MemoryStore, NewPasswordUser,
    UsernamePlugin,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

async fn application() -> Router {
    application_with_config(
        AuthConfig::new([43_u8; 32]).unwrap(),
        AdminConfig::default(),
    )
    .await
}

async fn application_with_config(mut config: AuthConfig, admin: AdminConfig) -> Router {
    config.trust_origin("http://localhost").unwrap();
    config.add_plugin(UsernamePlugin::default()).unwrap();
    config.add_plugin(AdminPlugin::new(admin)).unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    service
        .provision_password_user(NewPasswordUser {
            username: "luna".into(),
            name: "Luna".into(),
            email: None,
            password: "password".into(),
            role: "admin".into(),
        })
        .await
        .unwrap();
    lucid_auth::axum::router(service)
}

async fn create_user(app: &Router, cookie: &str, username: &str, role: &str) -> Value {
    let (status, body) = request_json(
        app,
        Request::post("/api/auth/admin/create-user")
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "email": format!("{username}@example.com"),
                    "password": "initial-password",
                    "name": username,
                    "role": role,
                    "data": { "username": username }
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn request_json(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let (mut parts, body) = request.into_parts();
    if parts.method == axum::http::Method::POST && parts.headers.contains_key(header::COOKIE) {
        parts.headers.insert(
            header::ORIGIN,
            "http://localhost".parse().expect("valid test origin"),
        );
    }
    let response = app
        .clone()
        .oneshot(Request::from_parts(parts, body))
        .await
        .unwrap();
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
                    "role": "user",
                    "data": { "username": "casey" }
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created["user"]["username"], "casey");
    assert_eq!(created["user"]["role"], "user");
    assert!(created["user"].get("mustChangePassword").is_none());
    let user_id = created["user"]["id"].as_str().unwrap();
    let (status, member_cookie) = sign_in(&app, "casey", "initial-password").await;
    assert_eq!(status, StatusCode::OK);
    let (status, session) = request_json(
        &app,
        Request::get("/api/auth/get-session")
            .header(header::COOKIE, member_cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(session["user"].get("mustChangePassword").is_none());

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
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(removed["code"], "YOU_CANNOT_REMOVE_YOURSELF");

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
    assert_eq!(duplicate["code"], "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL");

    let (status, missing) = request_json(
        &app,
        Request::get("/api/auth/admin/get-user?id=00000000-0000-0000-0000-000000000001")
            .header(header::COOKIE, owner_cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(missing["code"], "USER_NOT_FOUND");
}

#[tokio::test]
async fn custom_permissions_and_banned_message_match_admin_configuration() {
    let config = AuthConfig::new([44_u8; 32]).unwrap();
    let mut admin = AdminConfig::default();
    admin.set_role("support", AdminRole::new().allow("user", ["list", "get"]));
    admin.banned_user_message = "Contact the security team".into();
    let app = application_with_config(config, admin).await;
    let (_, admin_cookie) = sign_in(&app, "luna", "password").await;
    let support = create_user(&app, &admin_cookie, "supporter", "support").await;
    let support_id = support["user"]["id"].as_str().unwrap();
    let (_, support_cookie) = sign_in(&app, "supporter", "initial-password").await;

    let (status, permission) = request_json(
        &app,
        Request::post("/api/auth/admin/has-permission")
            .header(header::COOKIE, &support_cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "permissions": { "user": ["list", "get"] } }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(permission["success"], true);

    let (status, denied) = request_json(
        &app,
        Request::post("/api/auth/admin/create-user")
            .header(header::COOKIE, support_cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "email": "denied@example.com", "name": "Denied" }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(denied["code"], "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS");

    let (status, _) = request_json(
        &app,
        Request::post("/api/auth/admin/ban-user")
            .header(header::COOKIE, admin_cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "userId": support_id }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, banned) = request_json(
        &app,
        Request::post("/api/auth/sign-in/username")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "username": "supporter", "password": "initial-password" }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(banned["code"], "BANNED_USER");
    assert_eq!(banned["message"], "Contact the security team");
}

#[tokio::test]
async fn core_only_omits_admin_routes_and_user_fields() {
    let mut config = AuthConfig::new([45_u8; 32]).unwrap();
    config.trust_origin("http://localhost").unwrap();
    config.add_plugin(UsernamePlugin::default()).unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    service
        .provision_password_user(NewPasswordUser {
            username: "core_user".into(),
            name: "Core User".into(),
            email: None,
            password: "password".into(),
            role: "internal-placeholder".into(),
        })
        .await
        .unwrap();
    let app = lucid_auth::axum::router(service);
    let (_, cookie) = sign_in(&app, "core_user", "password").await;
    let (status, session) = request_json(
        &app,
        Request::get("/api/auth/get-session")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for field in ["role", "banned", "banReason", "banExpires"] {
        assert!(session["user"].get(field).is_none(), "unexpected {field}");
    }
    let (status, _) = request_json(
        &app,
        Request::get("/api/auth/admin/list-users")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
