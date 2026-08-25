use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, HaveIBeenPwnedOptions, HaveIBeenPwnedPlugin, MemoryStore,
    NewPasswordUser, PasswordBreachCheckError, PasswordBreachChecker, UsernamePlugin,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

struct RejectCompromised;

#[async_trait]
impl PasswordBreachChecker for RejectCompromised {
    async fn is_compromised(&self, password: &str) -> Result<bool, PasswordBreachCheckError> {
        Ok(password == "compromised password")
    }
}

#[tokio::test]
async fn change_password_checks_the_new_password_before_the_wrong_current_password() {
    let mut config = AuthConfig::new([145_u8; 32]).unwrap();
    config.trust_origin("http://localhost").unwrap();
    config.add_plugin(UsernamePlugin::default()).unwrap();
    config
        .add_plugin(HaveIBeenPwnedPlugin::with_checker(
            HaveIBeenPwnedOptions::default(),
            Arc::new(RejectCompromised),
        ))
        .unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    service
        .provision_password_user(NewPasswordUser {
            username: "route_order".into(),
            name: "Route Order".into(),
            email: None,
            password: "original password".into(),
            role: "user".into(),
        })
        .await
        .unwrap();
    let app = lucid_auth::axum::router(service.clone());
    let cookie = sign_in_cookie(&app).await;

    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/change-password")
                .header(header::ORIGIN, "http://localhost")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "currentPassword": "deliberately wrong",
                        "newPassword": "compromised password"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["code"], "PASSWORD_COMPROMISED");
    assert!(
        service
            .sign_in_username("route_order", "original password".into(), None, None)
            .await
            .is_ok()
    );
}

async fn sign_in_cookie(app: &axum::Router) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/username")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": "route_order", "password": "original password" })
                        .to_string(),
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
