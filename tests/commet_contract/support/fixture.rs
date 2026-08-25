use super::FakeCommetClient;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, CommetFeature, CommetOptions, CommetPlugin, MemoryStore,
    NewPasswordUser,
};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

pub(crate) struct Fixture {
    pub(crate) app: Router,
    pub(crate) client: Arc<FakeCommetClient>,
    pub(crate) cookie: Option<String>,
    pub(crate) user_id: Option<Uuid>,
}

pub(crate) async fn fixture(features: Vec<CommetFeature>, authenticated: bool) -> Fixture {
    let client = Arc::new(FakeCommetClient::default());
    let store = Arc::new(MemoryStore::default());
    let options = CommetOptions::new(client.clone(), features);
    let plugin = CommetPlugin::new(options);
    let mut config = AuthConfig::new([81_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config.add_plugin(plugin).unwrap();
    let service = Arc::new(AuthService::try_new(store, config).unwrap());
    let (cookie, user_id) = if authenticated {
        let user = service
            .provision_password_user(NewPasswordUser {
                username: "commet_contract_owner".into(),
                name: "Commet Contract Owner".into(),
                email: Some("owner@example.test".into()),
                password: "correct horse battery staple".into(),
                role: "owner".into(),
            })
            .await
            .unwrap();
        let signed_in = service
            .sign_in_username(
                "commet_contract_owner",
                "correct horse battery staple".into(),
                None,
                None,
            )
            .await
            .unwrap();
        (
            Some(format!(
                "better-auth.session_token={}",
                service.signed_cookie_value(&signed_in.token)
            )),
            Some(user.id),
        )
    } else {
        (None, None)
    };
    Fixture {
        app: lucid_auth::axum::router(service),
        client,
        cookie,
        user_id,
    }
}

pub(crate) async fn get(fixture: &Fixture, path: &str) -> (StatusCode, Value) {
    send(fixture, Request::get(path).body(Body::empty()).unwrap()).await
}

pub(crate) async fn post(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    send(
        fixture,
        Request::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

pub(crate) async fn post_absent(fixture: &Fixture, path: &str) -> (StatusCode, Value) {
    send(fixture, Request::post(path).body(Body::empty()).unwrap()).await
}

pub(crate) async fn post_with_content_type(
    fixture: &Fixture,
    path: &str,
    content_type: &str,
    body: &'static str,
) -> (StatusCode, Value) {
    send(
        fixture,
        Request::post(path)
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

async fn send(fixture: &Fixture, mut request: Request<Body>) -> (StatusCode, Value) {
    request
        .headers_mut()
        .insert(header::HOST, "app.example.test".parse().unwrap());
    request
        .headers_mut()
        .insert(header::ORIGIN, "http://app.example.test".parse().unwrap());
    if let Some(cookie) = &fixture.cookie {
        request
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
    }
    let response = fixture.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}
