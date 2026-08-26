use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthPlugin, AuthService, DEFAULT_PASSWORD_COMPROMISED_MESSAGE,
    HaveIBeenPwnedOptions, HaveIBeenPwnedPlugin, MemoryStore, NewPasswordUser,
    PASSWORD_COMPROMISED, PasswordBreachCheckError, PasswordBreachChecker,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

#[derive(Clone, Copy)]
enum CheckerResult {
    Uncompromised,
    Compromised,
    Status(u16),
    Unavailable,
}

struct RecordingChecker {
    result: CheckerResult,
    passwords: Mutex<Vec<String>>,
}

impl RecordingChecker {
    fn new(result: CheckerResult) -> Self {
        Self {
            result,
            passwords: Mutex::new(Vec::new()),
        }
    }

    fn passwords(&self) -> Vec<String> {
        self.passwords.lock().unwrap().clone()
    }
}

#[async_trait]
impl PasswordBreachChecker for RecordingChecker {
    async fn is_compromised(&self, password: &str) -> Result<bool, PasswordBreachCheckError> {
        self.passwords.lock().unwrap().push(password.to_owned());
        match self.result {
            CheckerResult::Uncompromised => Ok(false),
            CheckerResult::Compromised => Ok(true),
            CheckerResult::Status(status) => Err(PasswordBreachCheckError::Status(status)),
            CheckerResult::Unavailable => Err(PasswordBreachCheckError::Unavailable),
        }
    }
}

struct Fixture {
    app: Router,
    service: Arc<AuthService>,
    checker: Arc<RecordingChecker>,
}

fn fixture(options: HaveIBeenPwnedOptions, result: CheckerResult) -> Fixture {
    let checker = Arc::new(RecordingChecker::new(result));
    let mut config = AuthConfig::new([145_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    config.trust_origin("http://localhost").unwrap();
    config
        .add_plugin(HaveIBeenPwnedPlugin::with_checker(options, checker.clone()))
        .unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    let app = lucid_auth::axum::router(service.clone());
    Fixture {
        app,
        service,
        checker,
    }
}

async fn sign_up(app: &Router, email: &str, password: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-up/email")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost")
                .body(Body::from(
                    json!({
                        "name": "HIBP Contract",
                        "email": email,
                        "password": password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    (status, body)
}

#[test]
fn descriptor_is_the_exact_server_only_plugin_surface() {
    let plugin = HaveIBeenPwnedPlugin::with_checker(
        HaveIBeenPwnedOptions::default(),
        Arc::new(RecordingChecker::new(CheckerResult::Uncompromised)),
    );
    let descriptor = plugin.descriptor();

    assert_eq!(descriptor.id, "have-i-been-pwned");
    assert_eq!(descriptor.display_name, "Have I Been Pwned");
    assert_eq!(descriptor.version, "1.7.1");
    assert!(descriptor.dependencies.is_empty());
    assert!(descriptor.conflicts.is_empty());
    assert!(descriptor.endpoints.is_empty());
    assert!(descriptor.cookies.is_empty());
    assert!(descriptor.rate_limits.is_empty());
    assert!(descriptor.middleware.is_empty());
    assert!(descriptor.client.is_none());
    assert!(plugin.migrations().is_empty());
    assert!(plugin.schema().is_empty());
    assert!(plugin.rate_limits().is_empty());
    assert!(plugin.open_api_endpoints().is_empty());
    assert!(plugin.database_hooks().is_none());
    assert_eq!(PASSWORD_COMPROMISED, "PASSWORD_COMPROMISED");

    let options = plugin.options();
    assert_eq!(options.enabled, None);
    assert_eq!(
        options.paths(),
        [
            "/sign-up/email",
            "/change-password",
            "/reset-password",
            "/email-otp/reset-password",
            "/phone-number/reset-password",
            "/admin/create-user",
            "/admin/set-user-password",
        ]
    );
    assert_eq!(options.custom_password_compromised_message, None);
    assert_eq!(
        options.compromised_message(),
        DEFAULT_PASSWORD_COMPROMISED_MESSAGE
    );
}

#[tokio::test]
async fn absent_unrelated_custom_replacement_and_empty_paths_are_exact() {
    let absent = fixture(HaveIBeenPwnedOptions::default(), CheckerResult::Compromised);
    absent
        .service
        .provision_password_user(NewPasswordUser {
            username: "native_user".into(),
            name: "Native User".into(),
            email: None,
            password: "native password".into(),
            role: "user".into(),
        })
        .await
        .unwrap();
    assert!(absent.checker.passwords().is_empty());

    let replacement = fixture(
        HaveIBeenPwnedOptions {
            paths: Some(vec![
                "/change-password".into(),
                "/sign-up/email/".into(),
                "/SIGN-UP/EMAIL".into(),
            ]),
            ..HaveIBeenPwnedOptions::default()
        },
        CheckerResult::Compromised,
    );
    let (status, _) = sign_up(
        &replacement.app,
        "replacement@example.com",
        "replacement password",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(replacement.checker.passwords().is_empty());

    let exact_custom = fixture(
        HaveIBeenPwnedOptions {
            paths: Some(vec!["/sign-up/email".into()]),
            ..HaveIBeenPwnedOptions::default()
        },
        CheckerResult::Compromised,
    );
    let (status, _) = sign_up(
        &exact_custom.app,
        "custom@example.com",
        "custom selected password",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        exact_custom.checker.passwords(),
        ["custom selected password"]
    );

    let empty = fixture(
        HaveIBeenPwnedOptions {
            paths: Some(Vec::new()),
            ..HaveIBeenPwnedOptions::default()
        },
        CheckerResult::Compromised,
    );
    let (status, _) = sign_up(&empty.app, "empty@example.com", "empty paths password").await;
    assert_eq!(status, StatusCode::OK);
    assert!(empty.checker.passwords().is_empty());
}

#[tokio::test]
async fn explicitly_disabled_checks_never_contact_the_checker() {
    let disabled = fixture(
        HaveIBeenPwnedOptions {
            enabled: Some(false),
            ..HaveIBeenPwnedOptions::default()
        },
        CheckerResult::Compromised,
    );
    let (status, body) = sign_up(
        &disabled.app,
        "disabled@example.com",
        "disabled checker password",
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["token"].is_string());
    assert!(disabled.checker.passwords().is_empty());
}

#[tokio::test]
async fn compromised_messages_preserve_better_auth_truthiness_and_wire_shape() {
    for (index, configured, expected) in [
        (0, None, DEFAULT_PASSWORD_COMPROMISED_MESSAGE),
        (1, Some(""), DEFAULT_PASSWORD_COMPROMISED_MESSAGE),
        (2, Some("   "), "   "),
        (
            3,
            Some("Choose another password"),
            "Choose another password",
        ),
    ] {
        let fixture = fixture(
            HaveIBeenPwnedOptions {
                custom_password_compromised_message: configured.map(str::to_owned),
                ..HaveIBeenPwnedOptions::default()
            },
            CheckerResult::Compromised,
        );
        let password = format!("compromised password {index}");
        let (status, body) = sign_up(
            &fixture.app,
            &format!("message-{index}@example.com"),
            &password,
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body,
            json!({ "code": "PASSWORD_COMPROMISED", "message": expected })
        );
        assert_eq!(fixture.checker.passwords(), [password]);
    }
}

#[tokio::test]
async fn checker_failures_have_the_two_exact_500_json_shapes() {
    for (index, result, expected) in [
        (
            0,
            CheckerResult::Status(429),
            "Failed to check password. Status: 429",
        ),
        (
            1,
            CheckerResult::Unavailable,
            "Failed to check password. Please try again later.",
        ),
    ] {
        let fixture = fixture(HaveIBeenPwnedOptions::default(), result);
        let password = format!("checker failure password {index}");
        let (status, body) = sign_up(
            &fixture.app,
            &format!("failure-{index}@example.com"),
            &password,
        )
        .await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, json!({ "message": expected }));
        assert_eq!(fixture.checker.passwords(), [password]);
    }
}

#[tokio::test]
async fn an_uncompromised_password_continues_through_the_normal_signup() {
    let fixture = fixture(
        HaveIBeenPwnedOptions::default(),
        CheckerResult::Uncompromised,
    );
    let (status, body) = sign_up(
        &fixture.app,
        "safe@example.com",
        "safe password for contract",
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["token"].is_string());
    assert_eq!(body["user"]["email"], "safe@example.com");
    assert_eq!(fixture.checker.passwords(), ["safe password for contract"]);
}
