use super::FakeDodoClient;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, AuthStore, DodoPaymentsFeature, DodoPaymentsOptions,
    DodoPaymentsPlugin, MemoryStore, NewPasswordUser, UserProfileUpdate,
};
use serde_json::{Map, Value};
use std::sync::Arc;
use tower::ServiceExt;

pub(crate) struct Fixture {
    pub(crate) app: Router,
    pub(crate) client: Arc<FakeDodoClient>,
    pub(crate) cookie: Option<String>,
}

pub(crate) async fn fixture(
    features: Vec<DodoPaymentsFeature>,
    authenticated: bool,
    verified: bool,
) -> Fixture {
    let client = Arc::new(FakeDodoClient::default());
    let store = Arc::new(MemoryStore::default());
    let options = DodoPaymentsOptions::new(client.clone(), features);
    let plugin = DodoPaymentsPlugin::new(options, store.clone());
    let mut config = AuthConfig::new([71_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config.add_plugin(plugin).unwrap();
    let service = Arc::new(AuthService::try_new(store.clone(), config).unwrap());

    let cookie = if authenticated {
        Some(authenticate(&service, &store, verified).await)
    } else {
        None
    };

    Fixture {
        app: lucid_auth::axum::router(service),
        client,
        cookie,
    }
}

async fn authenticate(service: &AuthService, store: &MemoryStore, verified: bool) -> String {
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "dodo_contract_owner".into(),
            name: "Dodo Contract Owner".into(),
            email: Some("owner@example.test".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    store
        .update_user_profile(
            &user.id,
            UserProfileUpdate {
                additional_fields: Map::from_iter([(
                    "dodoCustomerId".into(),
                    Value::String("cus_contract".into()),
                )]),
                ..UserProfileUpdate::default()
            },
        )
        .await
        .unwrap();
    if verified {
        store
            .update_user_email(&user.id, &user.email, &user.email, true)
            .await
            .unwrap();
    }
    let signed_in = service
        .sign_in_username(
            "dodo_contract_owner",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(&signed_in.token)
    )
}

pub(crate) async fn post(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let mut request = Request::post(path)
        .header(header::HOST, "app.example.test")
        .header(header::ORIGIN, "http://app.example.test")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = &fixture.cookie {
        request = request.header(header::COOKIE, cookie);
    }
    send(
        &fixture.app,
        request.body(Body::from(body.to_string())).unwrap(),
    )
    .await
}

pub(crate) async fn get(fixture: &Fixture, path: &str) -> (StatusCode, Value) {
    let mut request = Request::get(path)
        .header(header::HOST, "app.example.test")
        .header(header::ORIGIN, "http://app.example.test");
    if let Some(cookie) = &fixture.cookie {
        request = request.header(header::COOKIE, cookie);
    }
    send(&fixture.app, request.body(Body::empty()).unwrap()).await
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}
