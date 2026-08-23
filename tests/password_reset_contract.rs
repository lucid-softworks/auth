use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::Duration;
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, MemoryStore, PasswordBreachChecker, PasswordResetCallback,
    PasswordResetEmail, PasswordResetEmailSender,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

#[derive(Default)]
struct ResetFixture {
    sent: Mutex<Vec<PasswordResetEmail>>,
    completed: Mutex<Vec<String>>,
}

#[async_trait]
impl PasswordResetEmailSender for ResetFixture {
    async fn send(&self, email: PasswordResetEmail) -> Result<(), AuthError> {
        self.sent.lock().await.push(email);
        Ok(())
    }
}

#[async_trait]
impl PasswordResetCallback for ResetFixture {
    async fn on_password_reset(&self, user: lucid_auth::AuthUser) -> Result<(), AuthError> {
        self.completed.lock().await.push(user.email);
        Ok(())
    }
}

struct RejectCompromised;

#[async_trait]
impl PasswordBreachChecker for RejectCompromised {
    async fn is_compromised(&self, password: &str) -> Result<bool, AuthError> {
        Ok(password == "compromised password")
    }
}

fn application(
    configure: impl FnOnce(&mut AuthConfig),
) -> (Router, Arc<AuthService>, Arc<ResetFixture>) {
    let fixture = Arc::new(ResetFixture::default());
    let mut config = AuthConfig::new([99_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    config.email_and_password.enabled = true;
    config.email_and_password.send_reset_password = Some(fixture.clone());
    config.email_and_password.on_password_reset = Some(fixture.clone());
    configure(&mut config);
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    (lucid_auth::axum::router(service.clone()), service, fixture)
}

async fn post(app: &Router, path: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

async fn signup(app: &Router, email: &str) -> String {
    let (status, body) = post(
        app,
        "/api/auth/sign-up/email",
        json!({
            "name": "Reset User",
            "email": email,
            "password": "correct horse battery staple"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["token"].as_str().unwrap().to_owned()
}

async fn request_reset(app: &Router, email: &str, redirect_to: Option<&str>) -> Value {
    let mut body = json!({ "email": email });
    if let Some(redirect_to) = redirect_to {
        body["redirectTo"] = Value::String(redirect_to.into());
    }
    let (status, body) = post(app, "/api/auth/request-password-reset", body).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

#[tokio::test]
async fn request_and_callback_match_exact_better_auth_fields() {
    let (app, _, fixture) = application(|_| {});
    signup(&app, "reset@example.com").await;
    let known = request_reset(&app, "RESET@example.com", Some("/choose?source=email")).await;
    let unknown = request_reset(&app, "missing@example.com", Some("/choose")).await;
    assert_eq!(known, unknown);
    assert_eq!(known["status"], true);
    assert_eq!(
        known["message"],
        "If this email exists in our system, check your email for the reset link"
    );

    let message = fixture.sent.lock().await[0].clone();
    assert!(message.url.contains("/api/auth/reset-password/"));
    assert!(
        message
            .url
            .contains("callbackURL=%2Fchoose%3Fsource%3Demail")
    );
    assert!(!message.url.contains("callbackUrl"));

    let (status, _) = post(
        &app,
        "/api/auth/request-password-reset",
        json!({
            "email": "reset@example.com",
            "redirectURL": "/wrong-alias"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let alias_message = fixture.sent.lock().await[1].clone();
    assert!(alias_message.url.ends_with("?callbackURL="));
    assert!(!alias_message.url.contains("wrong-alias"));

    let response = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/auth/reset-password/{}?callbackURL=%2Fchoose%3Fsource%3Demail",
                message.token
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers()[header::LOCATION],
        format!(
            "http://localhost/choose?source=email&token={}",
            message.token
        )
    );

    let invalid = app
        .clone()
        .oneshot(
            Request::get("/api/auth/reset-password/not-valid?callbackURL=%2Fchoose")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::FOUND);
    assert_eq!(
        invalid.headers()[header::LOCATION],
        "http://localhost/choose?error=INVALID_TOKEN"
    );

    let wrong_case = app
        .oneshot(
            Request::get(format!(
                "/api/auth/reset-password/{}?callbackUrl=%2Fwrong",
                message.token
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_case.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn body_and_query_tokens_reset_once_and_run_the_callback() {
    let (app, service, fixture) = application(|_| {});
    signup(&app, "body@example.com").await;
    request_reset(&app, "body@example.com", None).await;
    let body_token = fixture.sent.lock().await[0].token.clone();
    let (status, body) = post(
        &app,
        "/api/auth/reset-password",
        json!({ "newPassword": "a completely new password", "token": body_token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], true);
    assert!(
        service
            .sign_in_email(
                "body@example.com",
                "a completely new password".into(),
                None,
                None,
                None,
                None,
            )
            .await
            .is_ok()
    );
    let (status, replay) = post(
        &app,
        "/api/auth/reset-password",
        json!({ "newPassword": "another valid password", "token": body_token }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(replay["code"], "INVALID_TOKEN");

    request_reset(&app, "body@example.com", None).await;
    let query_token = fixture.sent.lock().await[1].token.clone();
    let (status, body) = post(
        &app,
        &format!("/api/auth/reset-password?token={query_token}"),
        json!({ "newPassword": "query supplied password", "token": "" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        fixture.completed.lock().await.as_slice(),
        ["body@example.com", "body@example.com"]
    );
}

#[tokio::test]
async fn password_rules_run_before_single_use_redemption() {
    let (app, service, fixture) = application(|config| {
        config.email_and_password.min_password_length = 12;
        config.password_breach_checker = Some(Arc::new(RejectCompromised));
    });
    signup(&app, "rules@example.com").await;
    request_reset(&app, "rules@example.com", None).await;
    let token = fixture.sent.lock().await[0].token.clone();

    let (status, error) = post(
        &app,
        "/api/auth/reset-password",
        json!({ "newPassword": "short", "token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "PASSWORD_TOO_SHORT");

    let (status, error) = post(
        &app,
        "/api/auth/reset-password",
        json!({ "newPassword": "compromised password", "token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "PASSWORD_COMPROMISED");

    let (status, body) = post(
        &app,
        "/api/auth/reset-password",
        json!({ "newPassword": "valid replacement password", "token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        service
            .sign_in_email(
                "rules@example.com",
                "valid replacement password".into(),
                None,
                None,
                None,
                None,
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn expiry_concurrency_and_session_revocation_are_atomic() {
    let (expired_app, _, expired_fixture) = application(|config| {
        config.email_and_password.reset_password_token_expires_in = Duration::milliseconds(1);
    });
    signup(&expired_app, "expired@example.com").await;
    request_reset(&expired_app, "expired@example.com", None).await;
    let expired_token = expired_fixture.sent.lock().await[0].token.clone();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let (status, error) = post(
        &expired_app,
        "/api/auth/reset-password",
        json!({ "newPassword": "valid replacement password", "token": expired_token }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "INVALID_TOKEN");

    let (app, service, fixture) = application(|config| {
        config.email_and_password.revoke_sessions_on_password_reset = true;
    });
    let session_token = signup(&app, "concurrent@example.com").await;
    request_reset(&app, "concurrent@example.com", None).await;
    let token = fixture.sent.lock().await[0].token.clone();
    let (left, right) = tokio::join!(
        service.reset_password(&token, "first replacement password".into()),
        service.reset_password(&token, "second replacement password".into())
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(matches!(
        left.err().or_else(|| right.err()),
        Some(AuthError::InvalidPasswordResetToken)
    ));
    assert!(service.session(&session_token).await.unwrap().is_none());
}

#[tokio::test]
async fn disabled_reset_returns_the_better_auth_error() {
    let mut config = AuthConfig::new([100_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    config.email_and_password.enabled = true;
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    let app = lucid_auth::axum::router(service);
    let (status, error) = post(
        &app,
        "/api/auth/request-password-reset",
        json!({ "email": "missing@example.com" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "RESET_PASSWORD_DISABLED");
    assert_eq!(error["message"], "Reset password isn't enabled");
}
