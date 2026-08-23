use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AdditionalField, AdditionalFieldType, AuthConfig, AuthError, AuthService, AuthStore,
    ChangeEmailConfirmation, ChangeEmailConfirmationSender, MemoryStore, UserProfileUpdate,
    VerificationEmail, VerificationEmailSender,
};
use serde_json::{Map, Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Default)]
struct Mailbox {
    verification: Mutex<Vec<VerificationEmail>>,
    confirmation: Mutex<Vec<ChangeEmailConfirmation>>,
}

#[async_trait]
impl VerificationEmailSender for Mailbox {
    async fn send(&self, email: VerificationEmail) -> Result<(), AuthError> {
        self.verification.lock().await.push(email);
        Ok(())
    }
}

#[async_trait]
impl ChangeEmailConfirmationSender for Mailbox {
    async fn send(&self, confirmation: ChangeEmailConfirmation) -> Result<(), AuthError> {
        self.confirmation.lock().await.push(confirmation);
        Ok(())
    }
}

struct Fixture {
    app: Router,
    store: Arc<MemoryStore>,
    mailbox: Arc<Mailbox>,
}

fn fixture(configure: impl FnOnce(&mut AuthConfig, &Arc<Mailbox>)) -> Fixture {
    let mailbox = Arc::new(Mailbox::default());
    let mut config = AuthConfig::new([47_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    config.email_and_password.enabled = true;
    config.email_verification.sender = Some(mailbox.clone());
    configure(&mut config, &mailbox);
    let store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(store.clone(), config));
    Fixture {
        app: lucid_auth::axum::router(service.clone()),
        store,
        mailbox,
    }
}

async fn post(app: &Router, path: &str, cookie: Option<&str>, body: Value) -> (StatusCode, Value) {
    let mut request = Request::post(path)
        .header(header::ORIGIN, "http://localhost")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    response_json(
        app.clone()
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap(),
    )
    .await
}

async fn get(app: &Router, path: &str, cookie: &str) -> (StatusCode, Value) {
    response_json(get_response(app, path, cookie).await).await
}

async fn get_response(app: &Router, path: &str, cookie: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::get(path)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let value = serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
        .unwrap_or(Value::Null);
    (status, value)
}

async fn signup(fixture: &Fixture, email: &str) -> (String, Value) {
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-up/email")
                .header(header::ORIGIN, "http://localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name": "Update User",
                        "email": email,
                        "password": "correct horse battery staple"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let (_, body) = response_json(response).await;
    (cookie, body)
}

fn configure_fields(config: &mut AuthConfig) {
    config.user.additional_fields.insert(
        "timezone".into(),
        AdditionalField::new(AdditionalFieldType::String),
    );
    config.user.additional_fields.insert(
        "managedFlag".into(),
        AdditionalField::new(AdditionalFieldType::Boolean)
            .input(false)
            .returned(false),
    );
    config.session.additional_fields.insert(
        "theme".into(),
        AdditionalField::new(AdditionalFieldType::String),
    );
    config.session.additional_fields.insert(
        "privateNote".into(),
        AdditionalField::new(AdditionalFieldType::String)
            .input(false)
            .returned(false),
    );
}

async fn assert_hidden_fields_are_not_returned(fixture: &Fixture, cookie: &str, user_id: Uuid) {
    fixture
        .store
        .update_user_profile(
            user_id,
            UserProfileUpdate {
                additional_fields: Map::from_iter([("managedFlag".into(), json!(true))]),
                ..UserProfileUpdate::default()
            },
        )
        .await
        .unwrap();
    let (_, current) = get(&fixture.app, "/api/auth/get-session", cookie).await;
    let session_id = Uuid::parse_str(current["session"]["id"].as_str().unwrap()).unwrap();
    fixture
        .store
        .update_session_fields(
            session_id,
            Map::from_iter([("privateNote".into(), json!("hidden"))]),
        )
        .await
        .unwrap();
    let (status, current) = get(&fixture.app, "/api/auth/get-session", cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(current["user"]["name"], "Updated Name");
    assert_eq!(current["user"]["timezone"], "Europe/London");
    assert!(current["user"].get("managedFlag").is_none());
    assert_eq!(current["session"]["theme"], "dark");
    assert!(current["session"].get("privateNote").is_none());
}

#[test]
fn additional_fields_cannot_replace_core_or_plugin_owned_fields() {
    for field in ["id", "email", "role", "impersonatedBy"] {
        let mut config = AuthConfig::new([48_u8; 32]).unwrap();
        let target = if field == "impersonatedBy" {
            &mut config.session.additional_fields
        } else {
            &mut config.user.additional_fields
        };
        target.insert(
            field.into(),
            AdditionalField::new(AdditionalFieldType::String),
        );
        assert!(matches!(
            AuthService::try_new(Arc::new(MemoryStore::default()), config),
            Err(AuthError::InvalidConfiguration(_))
        ));
    }
}

#[tokio::test]
async fn user_and_session_updates_accept_only_configured_mutable_fields() {
    let fixture = fixture(|config, _| configure_fields(config));
    let (cookie, signed_up) = signup(&fixture, "fields@example.com").await;
    let (status, updated) = post(
        &fixture.app,
        "/api/auth/update-user",
        Some(&cookie),
        json!({
            "name": "Updated Name",
            "image": null,
            "timezone": "Europe/London",
            "managedFlag": false,
            "email": false,
            "id": "attacker-controlled"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["status"], true);
    let (status, updated) = post(
        &fixture.app,
        "/api/auth/update-session",
        Some(&cookie),
        json!({
            "theme": "dark",
            "privateNote": null,
            "userId": Uuid::new_v4()
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["session"]["theme"], "dark");

    let user_id = Uuid::parse_str(signed_up["user"]["id"].as_str().unwrap()).unwrap();
    assert_hidden_fields_are_not_returned(&fixture, &cookie, user_id).await;

    for (path, body) in [
        ("/api/auth/update-user", json!({ "managedFlag": true })),
        (
            "/api/auth/update-user",
            json!({ "email": "other@example.com" }),
        ),
        ("/api/auth/update-session", json!({ "privateNote": "leak" })),
        ("/api/auth/update-session", json!({ "theme": 12 })),
    ] {
        let (status, _) = post(&fixture.app, path, Some(&cookie), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, unauthorized) = post(
        &fixture.app,
        "/api/auth/update-session",
        None,
        json!({ "theme": "light" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauthorized["code"], "UNAUTHORIZED");
    let (status, disabled) = post(
        &fixture.app,
        "/api/auth/change-email",
        Some(&cookie),
        json!({ "newEmail": "disabled@example.com" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(disabled["code"], "CHANGE_EMAIL_DISABLED");
}

#[path = "account_update_contract/change_email.rs"]
mod change_email;
