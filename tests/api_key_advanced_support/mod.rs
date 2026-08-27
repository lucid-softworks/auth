use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    ApiKeyConfiguration, ApiKeyGenerator, ApiKeyGetter, ApiKeyGetterValue, ApiKeyPlugin,
    ApiKeyValidator, AuthConfig, AuthError, AuthService, DatabaseIdGeneration,
    DatabaseIdGenerationRequest, DatabaseIdGenerationResult, DatabaseIdGenerationSize,
    DatabaseIdGenerator, MemorySecondaryStorage, MemoryStore, NewPasswordUser,
    PluginRequestContext, SecondaryStorage, UsernamePlugin,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

pub(crate) async fn application(
    configuration: ApiKeyConfiguration,
    id_callback: Option<Arc<IdCallback>>,
) -> (Router, Arc<AuthService>) {
    application_with_plugin(ApiKeyPlugin::new(configuration), id_callback).await
}

pub(crate) async fn application_with_configurations(
    configurations: Vec<ApiKeyConfiguration>,
) -> (Router, Arc<AuthService>) {
    application_with_plugin(ApiKeyPlugin::with_configurations(configurations), None).await
}

async fn application_with_plugin(
    plugin: ApiKeyPlugin,
    id_callback: Option<Arc<IdCallback>>,
) -> (Router, Arc<AuthService>) {
    let mut auth = AuthConfig::new([b'A'; 32]).unwrap();
    auth.set_base_url("http://localhost").unwrap();
    if let Some(callback) = id_callback {
        auth.database_id_generation = DatabaseIdGeneration::Callback(callback);
    }
    auth.add_plugin(UsernamePlugin::default()).unwrap();
    auth.add_plugin(plugin).unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), auth));
    provision(&service).await;
    (lucid_auth::axum::router(service.clone()), service)
}

pub(crate) async fn provision(service: &AuthService) {
    service
        .provision_password_user(NewPasswordUser {
            username: "api_owner".into(),
            name: "API Owner".into(),
            email: Some("api-owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
}

pub(crate) async fn owner_cookie(app: &Router) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/sign-in/username")
                .header(header::ORIGIN, "http://localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "username": "api_owner",
                        "password": "correct horse battery staple"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

pub(crate) async fn json_request<'a>(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::ORIGIN, "http://localhost");
    for (name, value) in headers {
        request = request.header(name, value);
    }
    if body.is_some() {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

pub(crate) struct FixedGenerator(pub(crate) String);

#[async_trait]
impl ApiKeyGenerator for FixedGenerator {
    async fn generate(&self, _length: usize, _prefix: Option<&str>) -> Result<String, AuthError> {
        Ok(self.0.clone())
    }
}

#[derive(Debug, Default)]
pub(crate) struct IdCallback {
    pub(crate) calls: Mutex<Vec<(String, DatabaseIdGenerationSize)>>,
}

impl DatabaseIdGenerator for IdCallback {
    fn generate(&self, request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        self.calls
            .lock()
            .unwrap()
            .push((request.model.into(), request.size));
        DatabaseIdGenerationResult::Id(if request.model == "apikey" {
            String::new()
        } else {
            format!("fixture-{}", request.model)
        })
    }
}

pub(crate) struct RecordingGetter {
    value: Mutex<ApiKeyGetterValue>,
    events: Arc<Mutex<Vec<String>>>,
}

impl RecordingGetter {
    pub(crate) fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            value: Mutex::new(ApiKeyGetterValue::Missing),
            events,
        }
    }

    pub(crate) fn set(&self, value: ApiKeyGetterValue) {
        *self.value.lock().unwrap() = value;
    }
}

impl ApiKeyGetter for RecordingGetter {
    fn get(&self, context: &PluginRequestContext) -> ApiKeyGetterValue {
        self.events
            .lock()
            .unwrap()
            .push(format!("getter:{}", context.path));
        self.value.lock().unwrap().clone()
    }
}

pub(crate) struct RecordingValidator {
    events: Arc<Mutex<Vec<String>>>,
    allowed: Mutex<bool>,
}

impl RecordingValidator {
    pub(crate) fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            events,
            allowed: Mutex::new(true),
        }
    }

    pub(crate) fn set(&self, allowed: bool) {
        *self.allowed.lock().unwrap() = allowed;
    }
}

#[async_trait]
impl ApiKeyValidator for RecordingValidator {
    async fn validate(&self, context: &PluginRequestContext, key: &str) -> Result<bool, AuthError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("validator:{}:{key}", context.path));
        Ok(*self.allowed.lock().unwrap())
    }
}

pub(crate) struct ObservableStorage {
    inner: MemorySecondaryStorage,
    events: Arc<Mutex<Vec<String>>>,
}

impl ObservableStorage {
    pub(crate) fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            inner: MemorySecondaryStorage::default(),
            events,
        }
    }
}

#[async_trait]
impl SecondaryStorage for ObservableStorage {
    async fn get(&self, key: &str) -> Result<Option<String>, AuthError> {
        self.events.lock().unwrap().push(format!("storage:{key}"));
        self.inner.get(key).await
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<String>, AuthError> {
        self.inner.get_and_delete(key).await
    }

    async fn set(&self, key: &str, value: String, ttl: Option<u64>) -> Result<(), AuthError> {
        self.inner.set(key, value, ttl).await
    }

    async fn delete(&self, key: &str) -> Result<(), AuthError> {
        self.inner.delete(key).await
    }

    async fn increment(&self, key: &str, ttl: Option<u64>) -> Result<u64, AuthError> {
        self.inner.increment(key, ttl).await
    }
}

#[test]
fn configuration_array_validation_uses_published_errors() {
    let mut missing_auth = AuthConfig::new([b'M'; 32]).unwrap();
    missing_auth
        .add_plugin(ApiKeyPlugin::with_configurations(vec![
            ApiKeyConfiguration {
                config_id: String::new(),
                ..ApiKeyConfiguration::default()
            },
        ]))
        .unwrap();
    let missing = match AuthService::try_new(Arc::new(MemoryStore::default()), missing_auth) {
        Ok(_) => panic!("missing configId unexpectedly passed validation"),
        Err(error) => error,
    };
    assert!(
        missing
            .to_string()
            .contains("configId is required for each API key configuration in the api-key plugin.")
    );

    let mut duplicate_auth = AuthConfig::new([b'D'; 32]).unwrap();
    duplicate_auth
        .add_plugin(ApiKeyPlugin::with_configurations(vec![
            ApiKeyConfiguration::default(),
            ApiKeyConfiguration::default(),
        ]))
        .unwrap();
    let duplicate = match AuthService::try_new(Arc::new(MemoryStore::default()), duplicate_auth) {
        Ok(_) => panic!("duplicate configId unexpectedly passed validation"),
        Err(error) => error,
    };
    assert!(
        duplicate.to_string().contains(
            "configId must be unique for each API key configuration in the api-key plugin."
        )
    );

    let mut empty_auth = AuthConfig::new([b'E'; 32]).unwrap();
    empty_auth
        .add_plugin(ApiKeyPlugin::with_configurations(Vec::new()))
        .unwrap();
    AuthService::try_new(Arc::new(MemoryStore::default()), empty_auth).unwrap();
}

#[tokio::test]
async fn configured_header_lookup_is_case_insensitive() {
    let configuration = ApiKeyConfiguration {
        storage: lucid_auth::ApiKeyStorage::SecondaryStorage,
        custom_storage: Some(Arc::new(MemorySecondaryStorage::default())),
        headers: vec!["X-Custom-Key".into()],
        default_key_length: 12,
        enable_session_for_api_keys: true,
        key_generator: Some(Arc::new(FixedGenerator("CaseHeaderKey".into()))),
        ..ApiKeyConfiguration::default()
    };
    let (app, _) = application(configuration, None).await;
    let cookie = owner_cookie(&app).await;
    let (_, created) = json_request(
        &app,
        "POST",
        "/api/auth/api-key/create",
        Some(json!({ "name": "case" })),
        [(header::COOKIE.as_str(), cookie.as_str())],
    )
    .await;
    let key = created["key"].as_str().unwrap();
    let (status, _) = json_request(
        &app,
        "GET",
        "/api/auth/get-session",
        None,
        [("x-custom-key", key)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn server_only_api_key_methods_are_not_http_routes() {
    let (app, _) = application(ApiKeyConfiguration::default(), None).await;
    let (verify_status, _) = json_request(
        &app,
        "POST",
        "/api/auth/api-key/verify",
        Some(json!({ "key": "not-a-key" })),
        std::iter::empty::<(&str, &str)>(),
    )
    .await;
    let (cleanup_status, _) = json_request(
        &app,
        "POST",
        "/api/auth/api-key/delete-all-expired-api-keys",
        Some(json!({})),
        std::iter::empty::<(&str, &str)>(),
    )
    .await;
    assert_eq!(verify_status, StatusCode::NOT_FOUND);
    assert_eq!(cleanup_status, StatusCode::NOT_FOUND);
}
