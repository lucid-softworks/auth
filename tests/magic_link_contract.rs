use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::Duration;
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, MagicLinkConfig, MagicLinkEmail, MagicLinkPlugin,
    MagicLinkRequestContext, MagicLinkSender, MagicLinkTokenGenerator, MagicLinkTokenHasher,
    MagicLinkTokenStorage, MemoryStore,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

#[path = "magic_link_contract/custom_token.rs"]
mod custom_token;

#[derive(Default)]
struct CapturingSender {
    messages: Mutex<Vec<(MagicLinkEmail, MagicLinkRequestContext)>>,
}

#[async_trait]
impl MagicLinkSender for CapturingSender {
    async fn send(
        &self,
        email: MagicLinkEmail,
        context: MagicLinkRequestContext,
    ) -> Result<(), AuthError> {
        self.messages.lock().await.push((email, context));
        Ok(())
    }
}

fn application(
    configure: impl FnOnce(&mut AuthConfig, &mut MagicLinkConfig),
) -> (Router, Arc<AuthService>, Arc<CapturingSender>) {
    let sender = Arc::new(CapturingSender::default());
    let mut auth = AuthConfig::new([101_u8; 32]).unwrap();
    auth.set_base_url("http://localhost").unwrap();
    auth.email_and_password.enabled = true;
    let mut magic = MagicLinkConfig::new(sender.clone());
    configure(&mut auth, &mut magic);
    auth.add_plugin(MagicLinkPlugin::new(magic)).unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), auth).unwrap());
    (lucid_auth::axum::router(service.clone()), service, sender)
}

async fn request_link(app: &Router, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/magic-link")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost")
                .header(header::USER_AGENT, "magic-link-contract")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    response_json(response).await
}

async fn response_json(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

#[tokio::test]
async fn plugin_is_optional_and_request_fields_match_exact_casing() {
    let mut config = AuthConfig::new([102_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    let absent = lucid_auth::axum::router(service)
        .oneshot(
            Request::post("/api/auth/sign-in/magic-link")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "email": "a@example.com" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(absent.status(), StatusCode::NOT_FOUND);

    let (app, _, sender) = application(|_, _| {});
    let (status, body) = request_link(
        &app,
        json!({
            "email": "Magic.User@Example.com",
            "name": "Magic User",
            "callbackURL": "/dashboard",
            "newUserCallbackURL": "/welcome",
            "errorCallbackURL": "/sign-in",
            "metadata": { "campaign": "launch" }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({ "status": true }));
    let sent = sender.messages.lock().await;
    let (message, context) = &sent[0];
    assert_eq!(message.email, "Magic.User@Example.com");
    assert_eq!(message.metadata.as_ref().unwrap()["campaign"], "launch");
    assert!(message.url.contains("callbackURL=%2Fdashboard"));
    assert!(message.url.contains("newUserCallbackURL=%2Fwelcome"));
    assert!(message.url.contains("errorCallbackURL=%2Fsign-in"));
    assert_eq!(context.origin.as_deref(), Some("http://localhost"));
    assert_eq!(context.user_agent.as_deref(), Some("magic-link-contract"));
    drop(sent);

    let (status, _) = request_link(
        &app,
        json!({
            "email": "alias@example.com",
            "callbackUrl": "/wrong",
            "newUserCallbackUrl": "/wrong-new"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let alias = &sender.messages.lock().await[1].0;
    assert!(alias.url.contains("callbackURL=%2F"));
    assert!(!alias.url.contains("wrong"));
}

#[tokio::test]
async fn urlencoded_form_requests_use_the_same_exact_fields() {
    let (app, _, sender) = application(|_, _| {});
    let response = app
        .oneshot(
            Request::post("/api/auth/sign-in/magic-link")
                .header(
                    header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .header(header::ORIGIN, "http://localhost")
                .body(Body::from(
                    "email=form%40example.com&name=Form+User&callbackURL=%2Fdashboard&callbackUrl=%2Fwrong",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let sent = sender.messages.lock().await;
    assert_eq!(sent[0].0.email, "form@example.com");
    assert!(sent[0].0.url.contains("callbackURL=%2Fdashboard"));
    assert!(!sent[0].0.url.contains("wrong"));
}

#[tokio::test]
async fn new_and_existing_users_follow_callback_and_single_use_rules() {
    let (app, service, sender) = application(|_, _| {});
    request_link(
        &app,
        json!({
            "email": "new@example.com",
            "name": "New User",
            "callbackURL": "/dashboard",
            "newUserCallbackURL": "/welcome"
        }),
    )
    .await;
    let token = sender.messages.lock().await[0].0.token.clone();
    let response = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/auth/magic-link/verify?token={token}&callbackURL=%2Fdashboard&newUserCallbackURL=%2Fwelcome"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers()[header::LOCATION],
        "http://localhost/welcome"
    );
    assert!(response.headers().contains_key(header::SET_COOKIE));
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let mut cookie_headers = axum::http::HeaderMap::new();
    cookie_headers.insert(header::COOKIE, cookie.parse().unwrap());
    let session_token = lucid_auth::axum::session_token(&service, &cookie_headers).unwrap();
    assert!(service.session(&session_token).await.unwrap().is_some());

    let replay = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/auth/magic-link/verify?token={token}&errorCallbackURL=%2Fretry"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::FOUND);
    assert_eq!(
        replay.headers()[header::LOCATION],
        "http://localhost/retry?error=INVALID_TOKEN"
    );

    request_link(
        &app,
        json!({ "email": "new@example.com", "callbackURL": "/dashboard" }),
    )
    .await;
    let token = sender.messages.lock().await[1].0.token.clone();
    let existing = app
        .oneshot(
            Request::get(format!(
                "/api/auth/magic-link/verify?token={token}&callbackURL=%2Fdashboard&newUserCallbackURL=%2Fwelcome"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(existing.status(), StatusCode::FOUND);
    assert_eq!(
        existing.headers()[header::LOCATION],
        "http://localhost/dashboard"
    );
}

#[tokio::test]
async fn json_verification_promotes_mailbox_and_revokes_unproven_access() {
    let (app, service, sender) = application(|_, magic| {
        magic.token_storage = MagicLinkTokenStorage::Hashed;
    });
    let (_, signup) = request_json(
        &app,
        "/api/auth/sign-up/email",
        json!({
            "name": "Unproven",
            "email": "unproven@example.com",
            "password": "correct horse battery staple"
        }),
    )
    .await;
    let old_session = signup["token"].as_str().unwrap().to_owned();
    request_link(&app, json!({ "email": "unproven@example.com" })).await;
    let token = sender.messages.lock().await[0].0.token.clone();
    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/api/auth/magic-link/verify?token={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (_, verified) = response_json(response).await;
    assert_eq!(verified["user"]["emailVerified"], true);
    assert!(verified["session"].get("assurance").is_none());
    assert!(service.session(&old_session).await.unwrap().is_none());
    assert!(
        service
            .sign_in_email(
                "unproven@example.com",
                "correct horse battery staple".into(),
                None,
                None,
                None,
                None,
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn disabled_signup_expiry_rate_limits_and_redirect_security_match() {
    let (app, _, sender) = application(|config, magic| {
        config.rate_limit.enabled = true;
        magic.disable_sign_up = true;
        magic.expires_in = Duration::milliseconds(1);
        magic.rate_limit_max = 5;
    });
    request_link(&app, json!({ "email": "disabled@example.com" })).await;
    let token = sender.messages.lock().await[0].0.token.clone();
    let disabled = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/auth/magic-link/verify?token={token}&errorCallbackURL=%2Fretry"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(disabled.status(), StatusCode::FOUND);
    assert_eq!(
        disabled.headers()[header::LOCATION],
        "http://localhost/retry?error=new_user_signup_disabled"
    );

    request_link(&app, json!({ "email": "expired@example.com" })).await;
    let token = sender.messages.lock().await[1].0.token.clone();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let expired = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/auth/magic-link/verify?token={token}&errorCallbackURL=%2Fretry"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(expired.status(), StatusCode::FOUND);
    assert_eq!(
        expired.headers()[header::LOCATION],
        "http://localhost/retry?error=INVALID_TOKEN"
    );

    for index in 0..3 {
        let (status, _) = request_link(
            &app,
            json!({ "email": format!("rate-{index}@example.com") }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, error) = request_link(&app, json!({ "email": "blocked@example.com" })).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        error,
        json!({ "message": "Too many requests. Please try again later." })
    );

    let untrusted = request_link(
        &application(|_, _| {}).0,
        json!({
            "email": "safe@example.com",
            "errorCallbackURL": "https://evil.example/steal"
        }),
    )
    .await;
    assert_eq!(untrusted.0, StatusCode::FORBIDDEN);
}

async fn request_json(app: &Router, path: &str, body: Value) -> (StatusCode, Value) {
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
    response_json(response).await
}
