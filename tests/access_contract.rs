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
    let mut config = AuthConfig::new([19_u8; 32]).unwrap();
    config.allow_anonymous = true;
    config.trust_origin("http://localhost").unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    for (username, name, role) in [("luna", "Luna", "owner"), ("casey", "Casey", "viewer")] {
        service
            .provision_password_user(NewPasswordUser {
                username: username.into(),
                name: name.into(),
                email: None,
                password: "password".into(),
                role: role.into(),
            })
            .await
            .unwrap();
    }
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
    let casey_id = users["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|user| user["username"] == "casey")
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/admin/set-role")
                .header(header::COOKIE, &owner_cookie)
                .header(header::ORIGIN, "http://localhost")
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
                .header(header::ORIGIN, "http://localhost")
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
                .header(header::ORIGIN, "http://localhost")
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
    let response = app.clone().oneshot(Request::post("/api/auth/guest-grants").header(header::COOKIE, owner_cookie).header(header::ORIGIN, "http://localhost").header(header::CONTENT_TYPE, "application/json").body(Body::from(json!({ "label": "Dog sitter", "permissions": ["devices:read"], "resourceScopes": ["room:kitchen"], "expiresAt": (chrono::Utc::now() + chrono::Duration::hours(1)), "maxUses": 1 }).to_string())).unwrap()).await.unwrap();
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
