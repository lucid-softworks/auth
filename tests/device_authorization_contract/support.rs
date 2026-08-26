pub(super) use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
pub(super) use chrono::{Duration, Utc};
pub(super) use http_body_util::BodyExt;
pub(super) use lucid_auth::{
    AuthConfig, AuthService, DeviceAuthorizationConfig, DeviceAuthorizationPlugin,
    DeviceAuthorizationStore, DeviceCode, DeviceCodeCreateOutcome, DeviceCodeStatus,
    MemoryDeviceAuthorizationStore, MemoryStore, NewPasswordUser,
};
pub(super) use serde_json::{Value, json};
pub(super) use std::sync::Arc;
pub(super) use tower::ServiceExt;
pub(super) use uuid::Uuid;

pub(super) const GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

pub(super) struct Fixture {
    pub(super) app: Router,
    pub(super) service: Arc<AuthService>,
    pub(super) devices: Arc<MemoryDeviceAuthorizationStore>,
    pub(super) cookie: String,
    pub(super) user_id: String,
}

pub(super) async fn fixture() -> Fixture {
    let mut config = DeviceAuthorizationConfig::default();
    config.interval = "0s".into();
    fixture_with(config).await
}

pub(super) async fn fixture_with(device_config: DeviceAuthorizationConfig) -> Fixture {
    let devices = Arc::new(MemoryDeviceAuthorizationStore::new());
    let mut config = AuthConfig::new([211_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config
        .add_plugin(DeviceAuthorizationPlugin::from_arc(
            device_config,
            devices.clone() as Arc<_>,
        ))
        .unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap());
    service
        .provision_password_user(NewPasswordUser {
            username: "device_owner".into(),
            name: "Device Owner".into(),
            email: Some("device-owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "user".into(),
        })
        .await
        .unwrap();
    let signed_in = service
        .sign_in_username(
            "device_owner",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    let cookie = format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(&signed_in.token)
    );
    let user_id = signed_in.session.user.id;
    let app = lucid_auth::axum::router(service.clone());
    Fixture {
        app,
        service,
        devices,
        cookie,
        user_id,
    }
}

pub(super) async fn request(
    app: &Router,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: impl Into<Body>,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::ORIGIN, "http://localhost");
    if let Some(content_type) = content_type {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    let response = app
        .clone()
        .oneshot(request.body(body.into()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, bytes.to_vec())
}

pub(super) async fn json_request(
    app: &Router,
    method: &str,
    path: &str,
    body: Value,
    cookie: Option<&str>,
) -> (StatusCode, HeaderMap, Value) {
    let (status, headers, bytes) = request(
        app,
        method,
        path,
        Some("application/json"),
        Body::from(body.to_string()),
        cookie,
    )
    .await;
    (status, headers, serde_json::from_slice(&bytes).unwrap())
}

pub(super) async fn issue(app: &Router) -> Value {
    let (status, _, body) = json_request(
        app,
        "POST",
        "/api/auth/device/code",
        json!({"client_id": "native-client", "scope": "openid profile"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

pub(super) async fn token(app: &Router, device_code: &str) -> (StatusCode, HeaderMap, Value) {
    json_request(
        app,
        "POST",
        "/api/auth/device/token",
        json!({
            "grant_type": GRANT,
            "device_code": device_code,
            "client_id": "native-client"
        }),
        None,
    )
    .await
}

pub(super) fn record(
    device_code: &str,
    user_code: &str,
    user_id: Option<String>,
    status: DeviceCodeStatus,
) -> DeviceCode {
    DeviceCode {
        id: Uuid::new_v4(),
        device_code: device_code.into(),
        user_code: user_code.into(),
        user_id,
        expires_at: Utc::now() + Duration::minutes(30),
        status,
        last_polled_at: None,
        polling_interval: Some(0.0),
        client_id: Some("native-client".into()),
        scope: Some("openid profile".into()),
        resources: None,
        oauth_client_id: None,
    }
}

pub(super) async fn insert(store: &dyn DeviceAuthorizationStore, record: DeviceCode) {
    assert!(matches!(
        store.create_device_code(record).await.unwrap(),
        DeviceCodeCreateOutcome::Created(_)
    ));
}
