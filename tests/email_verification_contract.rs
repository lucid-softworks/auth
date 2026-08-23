use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::Duration;
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, MemoryStore, VerificationEmail, VerificationEmailSender,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

#[derive(Default)]
struct CapturingSender {
    sent: Mutex<Vec<VerificationEmail>>,
}

#[async_trait]
impl VerificationEmailSender for CapturingSender {
    async fn send(&self, email: VerificationEmail) -> Result<(), AuthError> {
        self.sent.lock().await.push(email);
        Ok(())
    }
}

fn application(
    configure: impl FnOnce(&mut AuthConfig),
) -> (Router, Arc<AuthService>, Arc<CapturingSender>) {
    let sender = Arc::new(CapturingSender::default());
    let mut config = AuthConfig::new([98_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    config.email_and_password.enabled = true;
    config.email_verification.sender = Some(sender.clone());
    configure(&mut config);
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    (lucid_auth::axum::router(service.clone()), service, sender)
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
    let body =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    (status, body)
}

async fn signup(app: &Router, email: &str) {
    let (status, body) = post(
        app,
        "/api/auth/sign-up/email",
        json!({
            "name": "Verification User",
            "email": email,
            "password": "correct horse battery staple",
            "callbackURL": "/verified"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn signup_delivery_and_verification_are_single_use_and_auto_sign_in() {
    let (app, service, sender) = application(|config| {
        config.email_and_password.require_email_verification = true;
        config.email_verification.auto_sign_in_after_verification = true;
    });
    signup(&app, "Verify.Me@Example.com").await;
    let email = sender.sent.lock().await[0].clone();
    assert_eq!(email.user.email, "verify.me@example.com");
    assert!(email.url.contains("callbackURL=%2Fverified"));

    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/api/auth/verify-email?token={}", email.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(header::SET_COOKIE));
    assert!(
        service
            .sign_in_email(
                "verify.me@example.com",
                "correct horse battery staple".into(),
                None,
                None,
                None,
                None,
            )
            .await
            .is_ok()
    );

    let replay = app
        .oneshot(
            Request::get(format!("/api/auth/verify-email?token={}", email.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn concurrent_verification_allows_exactly_one_consumer() {
    let (app, service, sender) = application(|config| {
        config.email_and_password.require_email_verification = true;
    });
    signup(&app, "concurrent@example.com").await;
    let token = sender.sent.lock().await[0].token.clone();
    let (left, right) = tokio::join!(
        service.verify_email_token(&token, None),
        service.verify_email_token(&token, None),
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let error = left.err().or_else(|| right.err()).unwrap();
    assert!(matches!(error, AuthError::InvalidToken));
}

#[tokio::test]
async fn expired_tokens_are_consumed_and_reported_as_expired() {
    let (app, service, sender) = application(|config| {
        config.email_and_password.require_email_verification = true;
        config.email_verification.expires_in = Duration::milliseconds(1);
    });
    signup(&app, "expired@example.com").await;
    let token = sender.sent.lock().await[0].token.clone();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    assert!(matches!(
        service.verify_email_token(&token, None).await,
        Err(AuthError::TokenExpired)
    ));
    assert!(matches!(
        service.verify_email_token(&token, None).await,
        Err(AuthError::InvalidToken)
    ));
}

#[tokio::test]
async fn send_route_and_redirect_errors_match_better_auth_casing() {
    let (app, _, sender) = application(|_| {});
    signup(&app, "send@example.com").await;
    let (status, body) = post(
        &app,
        "/api/auth/send-verification-email",
        json!({ "email": "send@example.com", "callbackURL": "/done" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], true);
    assert_eq!(sender.sent.lock().await.len(), 1);

    let redirected = app
        .clone()
        .oneshot(
            Request::get("/api/auth/verify-email?token=invalid&callbackURL=%2Ferror")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(redirected.status(), StatusCode::FOUND);
    assert_eq!(
        redirected.headers()[header::LOCATION],
        "/error?error=INVALID_TOKEN"
    );

    let untrusted = app
        .clone()
        .oneshot(
            Request::get(
                "/api/auth/verify-email?token=invalid&callbackURL=https%3A%2F%2Fevil.example%2F",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(untrusted.status(), StatusCode::FORBIDDEN);

    let wrong_case = app
        .oneshot(
            Request::get("/api/auth/verify-email?token=invalid&callbackUrl=%2Fwrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_case.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn required_signin_can_send_again_without_authenticating() {
    let (app, _, sender) = application(|config| {
        config.email_and_password.require_email_verification = true;
        config.email_verification.send_on_sign_up = Some(false);
        config.email_verification.send_on_sign_in = true;
    });
    signup(&app, "signin@example.com").await;
    assert!(sender.sent.lock().await.is_empty());
    let (status, error) = post(
        &app,
        "/api/auth/sign-in/email",
        json!({
            "email": "signin@example.com",
            "password": "correct horse battery staple",
            "callbackURL": "/after-signin"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error["code"], "EMAIL_NOT_VERIFIED");
    assert_eq!(sender.sent.lock().await.len(), 1);
}
