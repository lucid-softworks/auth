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

async fn application(trusted_origins: &[&str]) -> Router {
    let mut config = AuthConfig::new([89_u8; 32]).unwrap();
    for origin in trusted_origins {
        config.trust_origin(origin).unwrap();
    }
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

fn sign_in_request(callback_url: Option<&str>) -> Request<Body> {
    let mut body = json!({ "username": "luna", "password": "password" });
    if let Some(callback_url) = callback_url {
        body["callbackURL"] = callback_url.into();
    }
    Request::post("/api/auth/sign-in/username")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn allows_configured_and_request_host_origins() {
    let configured = application(&["https://app.example.com"]).await;
    let response = configured
        .oneshot(
            Request::post("/api/auth/sign-in/username")
                .header(header::ORIGIN, "https://app.example.com")
                .header("sec-fetch-site", "cross-site")
                .header("sec-fetch-mode", "cors")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": "luna", "password": "password" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let same_origin = application(&[]).await;
    let response = same_origin
        .oneshot(
            Request::post("/api/auth/sign-in/username")
                .header(header::HOST, "auth.example.com")
                .header(header::ORIGIN, "http://auth.example.com")
                .header("sec-fetch-site", "same-origin")
                .header("sec-fetch-mode", "cors")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": "luna", "password": "password" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn rejects_untrusted_and_missing_browser_origins() {
    let app = application(&["https://app.example.com"]).await;
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/username")
                .header(header::ORIGIN, "https://app.example.com.evil.test")
                .header("sec-fetch-site", "cross-site")
                .header("sec-fetch-mode", "cors")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": "luna", "password": "password" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_json(response).await["code"], "INVALID_ORIGIN");

    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/username")
                .header(header::ORIGIN, "null")
                .header("sec-fetch-site", "cross-site")
                .header("sec-fetch-mode", "cors")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": "luna", "password": "password" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(response).await["code"],
        "MISSING_OR_NULL_ORIGIN"
    );

    let response = app.clone().oneshot(sign_in_request(None)).await.unwrap();
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let response = app
        .oneshot(
            Request::post("/api/auth/sign-out")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(response).await["code"],
        "MISSING_OR_NULL_ORIGIN"
    );
}

#[tokio::test]
async fn blocks_cross_site_navigation_login() {
    let response = application(&["https://app.example.com"])
        .await
        .oneshot(
            Request::post("/api/auth/sign-in/username")
                .header(header::ORIGIN, "https://app.example.com")
                .header("sec-fetch-site", "cross-site")
                .header("sec-fetch-mode", "navigate")
                .header("sec-fetch-dest", "document")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": "luna", "password": "password" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(response).await["code"],
        "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED"
    );
}

#[tokio::test]
async fn validates_relative_and_absolute_callback_urls_before_login() {
    let app = application(&["https://app.example.com", "myapp://auth/callback"]).await;
    for callback in [
        "/dashboard",
        "https://app.example.com/dashboard",
        "myapp://auth/callback/complete",
    ] {
        let response = app
            .clone()
            .oneshot(sign_in_request(Some(callback)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["url"], callback);
    }

    for callback in [
        "https://evil.test/dashboard",
        "//evil.test/dashboard",
        "/%2fevil.test/dashboard",
    ] {
        let response = app
            .clone()
            .oneshot(sign_in_request(Some(callback)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        assert_eq!(
            response_json(response).await["code"],
            "INVALID_CALLBACK_URL"
        );
    }
}

#[tokio::test]
async fn validates_every_better_auth_redirect_field_and_exact_casing() {
    let app = application(&["https://app.example.com"]).await;
    for (field, code) in [
        ("redirectTo", "INVALID_REDIRECT_URL"),
        ("errorCallbackURL", "INVALID_ERROR_CALLBACK_URL"),
        ("newUserCallbackURL", "INVALID_NEW_USER_CALLBACK_URL"),
    ] {
        let mut body = json!({ "username": "luna", "password": "password" });
        body[field] = "https://evil.test".into();
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/auth/sign-in/username")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        assert_eq!(response_json(response).await["code"], code);
    }

    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/username?callbackURL=https%3A%2F%2Fevil.test")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": "luna", "password": "password" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(response).await["code"],
        "INVALID_CALLBACK_URL"
    );

    let response = app
        .oneshot(
            Request::post("/api/auth/sign-in/username")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "username": "luna",
                        "password": "password",
                        "callbackUrl": "https://evil.test"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["url"], Value::Null);
}
