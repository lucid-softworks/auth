use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, DatabaseIdGeneration, DatabaseIdGenerationRequest,
    DatabaseIdGenerationResult, DatabaseIdGenerationSize, DatabaseIdGenerator,
    MemorySecondaryStorage, MemoryStore,
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tower::ServiceExt;

#[derive(Debug)]
struct RecordingGenerator {
    special: DatabaseIdGenerationResult,
    calls: Mutex<Vec<(String, DatabaseIdGenerationSize)>>,
    sequence: AtomicUsize,
}

impl RecordingGenerator {
    fn new(special: DatabaseIdGenerationResult) -> Self {
        Self {
            special,
            calls: Mutex::new(Vec::new()),
            sequence: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> Vec<(String, DatabaseIdGenerationSize)> {
        self.calls.lock().unwrap().clone()
    }
}

impl DatabaseIdGenerator for RecordingGenerator {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        self.calls
            .lock()
            .unwrap()
            .push((request.model.into(), request.size));
        if request.size == DatabaseIdGenerationSize::Undefined {
            return self.special.clone();
        }
        DatabaseIdGenerationResult::Id(format!(
            "ordinary-{}-{}",
            request.model,
            self.sequence.fetch_add(1, Ordering::Relaxed)
        ))
    }
}

fn application(configure: impl FnOnce(&mut AuthConfig)) -> (Router, Arc<AuthService>) {
    let mut config = AuthConfig::new([b'X'; 32]).unwrap();
    config.email_and_password.enabled = true;
    config.email_and_password.require_email_verification = true;
    config.trust_origin("http://localhost").unwrap();
    configure(&mut config);
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    (lucid_auth::axum::router(service.clone()), service)
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

async fn sign_up(app: &Router, email: &str) -> Value {
    let (status, body) = post(
        app,
        "/api/auth/sign-up/email",
        json!({
            "name": "Context ID User",
            "email": email,
            "password": "correct horse battery staple"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

#[tokio::test]
async fn synthetic_duplicate_users_apply_the_javascript_falsey_fallback() {
    for (special, retained) in [
        (DatabaseIdGenerationResult::Id(String::new()), None),
        (DatabaseIdGenerationResult::Defer, None),
        (
            DatabaseIdGenerationResult::Id("callback-synthetic".into()),
            Some("callback-synthetic"),
        ),
    ] {
        let generator = Arc::new(RecordingGenerator::new(special));
        let (app, _) = application(|config| {
            config.database_id_generation = DatabaseIdGeneration::Callback(generator.clone());
        });
        sign_up(&app, "synthetic@example.com").await;
        let synthetic = sign_up(&app, "SYNTHETIC@example.com").await;
        let second_synthetic = sign_up(&app, "synthetic@example.com").await;
        let id = synthetic["user"]["id"].as_str().unwrap();
        let second_id = second_synthetic["user"]["id"].as_str().unwrap();
        if let Some(retained) = retained {
            assert_eq!(id, retained);
            assert_eq!(second_id, retained);
        } else {
            assert_base62(id, 32);
            assert_base62(second_id, 32);
            assert_ne!(id, second_id);
        }
        assert_eq!(
            generator
                .calls()
                .into_iter()
                .filter(|(_, size)| *size == DatabaseIdGenerationSize::Undefined)
                .collect::<Vec<_>>(),
            [
                ("user".into(), DatabaseIdGenerationSize::Undefined),
                ("user".into(), DatabaseIdGenerationSize::Undefined),
            ]
        );
    }
}

#[tokio::test]
async fn legacy_context_generator_precedes_the_database_id_callback() {
    let legacy = Arc::new(RecordingGenerator::new(DatabaseIdGenerationResult::Id(
        "legacy-synthetic".into(),
    )));
    let database = Arc::new(RecordingGenerator::new(DatabaseIdGenerationResult::Id(
        "database-synthetic".into(),
    )));
    let (app, _) = application(|config| {
        config.legacy_id_generator = Some(legacy.clone());
        config.database_id_generation = DatabaseIdGeneration::Callback(database.clone());
    });
    sign_up(&app, "legacy@example.com").await;
    let synthetic = sign_up(&app, "LEGACY@example.com").await;
    assert_eq!(synthetic["user"]["id"], "legacy-synthetic");
    assert!(
        database
            .calls()
            .iter()
            .all(|(_, size)| *size != DatabaseIdGenerationSize::Undefined)
    );
    assert!(
        legacy
            .calls()
            .contains(&("user".into(), DatabaseIdGenerationSize::Undefined))
    );
}

#[tokio::test]
async fn secondary_only_sessions_use_the_strict_defer_fallback() {
    for (special, expected) in [
        (DatabaseIdGenerationResult::Id(String::new()), Some("")),
        (DatabaseIdGenerationResult::Defer, None),
        (
            DatabaseIdGenerationResult::Id("callback-session".into()),
            Some("callback-session"),
        ),
    ] {
        let generator = Arc::new(RecordingGenerator::new(special));
        let (app, service) = application(|config| {
            config.email_and_password.require_email_verification = false;
            config.database_id_generation = DatabaseIdGeneration::Callback(generator.clone());
            config.secondary_storage = Some(Arc::new(MemorySecondaryStorage::default()));
        });
        let signed_up = sign_up(&app, "secondary@example.com").await;
        let token = signed_up["token"].as_str().unwrap();
        assert_base62(token, 32);
        let stored = service.session(token).await.unwrap().unwrap();
        let second = sign_up(&app, "secondary-second@example.com").await;
        let second_token = second["token"].as_str().unwrap();
        let second_stored = service.session(second_token).await.unwrap().unwrap();
        if let Some(expected) = expected {
            assert_eq!(stored.session.id, expected);
            assert_eq!(second_stored.session.id, expected);
        } else {
            assert_base62(&stored.session.id, 32);
            assert_base62(&second_stored.session.id, 32);
            assert_ne!(stored.session.id, second_stored.session.id);
        }
        assert_eq!(
            generator
                .calls()
                .into_iter()
                .filter(|(_, size)| *size == DatabaseIdGenerationSize::Undefined)
                .collect::<Vec<_>>(),
            [
                ("session".into(), DatabaseIdGenerationSize::Undefined),
                ("session".into(), DatabaseIdGenerationSize::Undefined),
            ]
        );
    }
}

fn assert_base62(value: &str, length: usize) {
    assert_eq!(value.len(), length);
    assert!(value.bytes().all(|byte| byte.is_ascii_alphanumeric()));
}
