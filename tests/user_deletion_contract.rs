use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AfterAuthEvent, AuthConfig, AuthError, AuthPlugin, AuthService, AuthStore, BeforeAuthEvent,
    DeleteAccountVerification, DeleteAccountVerificationSender, DeleteUserConfig, EmailSignUpInput,
    MemoryStore, PluginDescriptor, UserDeletionCallback,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

#[derive(Clone)]
struct Fixture {
    app: Router,
    service: Arc<AuthService>,
    store: Arc<MemoryStore>,
}

async fn fixture(delete_user: DeleteUserConfig, observer: Option<DeletionObserver>) -> Fixture {
    let mut config = AuthConfig::new([127_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    config.set_base_url("http://localhost").unwrap();
    config.user.delete_user = delete_user;
    if let Some(observer) = observer {
        config.add_plugin(observer).unwrap();
    }
    let store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(store.clone(), config));
    Fixture {
        app: lucid_auth::axum::router(service.clone()),
        service,
        store,
    }
}

async fn account(fixture: &Fixture, email: &str) -> (String, lucid_auth::AuthUser) {
    let signup = fixture
        .service
        .sign_up_email(
            EmailSignUpInput {
                name: "Delete Me".into(),
                email: email.into(),
                password: "correct horse battery staple".into(),
                image: None,
                callback_url: None,
                remember_me: None,
                username: None,
                display_username: None,
                additional_fields: serde_json::Map::new(),
            },
            None,
            None,
        )
        .await
        .unwrap();
    let token = signup.token.unwrap();
    (
        format!(
            "better-auth.session_token={}",
            fixture.service.signed_cookie_value(&token)
        ),
        signup.user,
    )
}

async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

fn delete_request(cookie: &str, body: Value) -> Request<Body> {
    Request::post("/api/auth/delete-user")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "http://localhost")
        .header(header::COOKIE, cookie)
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[derive(Clone)]
struct RecordCallback {
    name: &'static str,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl UserDeletionCallback for RecordCallback {
    async fn call(&self, _user: lucid_auth::AuthUser) -> Result<(), AuthError> {
        self.events.lock().await.push(self.name);
        Ok(())
    }
}

#[derive(Clone)]
struct DeletionObserver {
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl AuthPlugin for DeletionObserver {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "deletion-observer",
            display_name: "Deletion observer",
            version: "1.0.0",
            provenance: lucid_auth::PluginProvenance::lucid_extension(),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(&[]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    async fn before(&self, event: &BeforeAuthEvent) -> Result<(), AuthError> {
        if matches!(event, BeforeAuthEvent::UserDelete { .. }) {
            self.events.lock().await.push("plugin-before");
        }
        Ok(())
    }

    async fn after(&self, event: &AfterAuthEvent) {
        if matches!(event, AfterAuthEvent::UserDeleted { .. }) {
            self.events.lock().await.push("plugin-after");
        }
    }
}

#[tokio::test]
async fn password_deletion_clears_the_account_and_runs_callbacks_in_order() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let config = DeleteUserConfig {
        enabled: true,
        before_delete: Some(Arc::new(RecordCallback {
            name: "configured-before",
            events: events.clone(),
        })),
        after_delete: Some(Arc::new(RecordCallback {
            name: "configured-after",
            events: events.clone(),
        })),
        ..DeleteUserConfig::default()
    };
    let fixture = fixture(
        config,
        Some(DeletionObserver {
            events: events.clone(),
        }),
    )
    .await;
    let (cookie, user) = account(&fixture, "password-delete@example.com").await;

    let wrong = fixture
        .app
        .clone()
        .oneshot(delete_request(&cookie, json!({ "password": "wrong" })))
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(wrong).await["code"], "INVALID_PASSWORD");

    let deleted = fixture
        .app
        .clone()
        .oneshot(delete_request(
            &cookie,
            json!({ "password": "correct horse battery staple" }),
        ))
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    assert!(
        deleted
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(response_json(deleted).await["message"], "User deleted");
    assert!(
        fixture
            .store
            .find_user_by_id(user.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        *events.lock().await,
        [
            "configured-before",
            "plugin-before",
            "plugin-after",
            "configured-after"
        ]
    );
}

#[derive(Clone, Default)]
struct CapturingSender {
    sent: Arc<Mutex<Vec<DeleteAccountVerification>>>,
}

#[async_trait]
impl DeleteAccountVerificationSender for CapturingSender {
    async fn send(&self, verification: DeleteAccountVerification) -> Result<(), AuthError> {
        self.sent.lock().await.push(verification);
        Ok(())
    }
}

#[tokio::test]
async fn verification_tokens_are_purpose_bound_single_use_and_redirect_safely() {
    let sender = CapturingSender::default();
    let fixture = fixture(
        DeleteUserConfig {
            enabled: true,
            send_delete_account_verification: Some(Arc::new(sender.clone())),
            ..DeleteUserConfig::default()
        },
        None,
    )
    .await;
    let (cookie, user) = account(&fixture, "token-delete@example.com").await;
    let requested = fixture
        .app
        .clone()
        .oneshot(delete_request(
            &cookie,
            json!({ "callbackURL": "/goodbye" }),
        ))
        .await
        .unwrap();
    assert_eq!(requested.status(), StatusCode::OK);
    assert_eq!(
        response_json(requested).await["message"],
        "Verification email sent"
    );
    assert!(
        fixture
            .store
            .find_user_by_id(user.id)
            .await
            .unwrap()
            .is_some()
    );
    let sent = sender.sent.lock().await;
    let message = sent.last().unwrap();
    assert_eq!(message.user.id, user.id);
    assert!(message.url.contains("callbackURL=%2Fgoodbye"));
    assert_eq!(message.token.len(), 32);
    let token = message.token.clone();
    drop(sent);

    let invalid = fixture
        .app
        .clone()
        .oneshot(delete_request(&cookie, json!({ "token": "invalid" })))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::NOT_FOUND);
    assert_eq!(response_json(invalid).await["code"], "INVALID_TOKEN");

    let callback = fixture
        .app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/auth/delete-user/callback?token={token}&callbackURL=%2Fgoodbye"
            ))
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(callback.headers()[header::LOCATION], "/goodbye");
    assert!(
        fixture
            .store
            .find_user_by_id(user.id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn disabled_and_stale_deletion_match_official_errors() {
    let disabled = fixture(DeleteUserConfig::default(), None).await;
    let (cookie, _) = account(&disabled, "disabled-delete@example.com").await;
    let response = disabled
        .app
        .oneshot(delete_request(&cookie, json!({})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response_json(response).await["code"], "NOT_FOUND");

    let config = DeleteUserConfig {
        enabled: true,
        ..DeleteUserConfig::default()
    };
    let stale = fixture(config, None).await;
    let (_cookie, user) = account(&stale, "stale-delete@example.com").await;
    let old_token = "old-session-token";
    let old = chrono::Utc::now() - chrono::Duration::days(2);
    let session = lucid_auth::AuthSession {
        id: uuid::Uuid::new_v4(),
        user_id: user.id,
        token: old_token.into(),
        actor_user_id: None,
        authentication_method: Some(lucid_auth::AuthenticationMethod::Password),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        created_at: old,
        updated_at: old,
        ip_address: None,
        user_agent: None,
        additional_fields: serde_json::Map::new(),
    };
    stale.store.create_session(session).await.unwrap();
    let stale_cookie = format!(
        "better-auth.session_token={}",
        stale.service.signed_cookie_value(old_token)
    );
    let expired = stale
        .app
        .clone()
        .oneshot(delete_request(&stale_cookie, json!({})))
        .await
        .unwrap();
    assert_eq!(expired.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(expired).await["code"], "SESSION_EXPIRED");
    assert!(
        stale
            .store
            .find_user_by_id(user.id)
            .await
            .unwrap()
            .is_some()
    );

    let deleted = stale
        .app
        .oneshot(delete_request(
            &stale_cookie,
            json!({ "password": "correct horse battery staple" }),
        ))
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    assert!(
        stale
            .store
            .find_user_by_id(user.id)
            .await
            .unwrap()
            .is_none()
    );
}
