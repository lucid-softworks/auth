use super::ProjectionClient;
use axum::{
    Router,
    body::{Body, Bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, CommetFeature, CommetOptions, CommetPlugin, CommetPortalOptions,
    CommetSubscriptionsOptions, MemoryStore, NewPasswordUser,
};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

pub(crate) struct Fixture {
    pub(crate) app: Router,
    pub(crate) client: Arc<ProjectionClient>,
    cookie: String,
}

pub(crate) async fn fixture(return_url: Option<&str>) -> Fixture {
    let client = Arc::new(ProjectionClient::default());
    let features = vec![
        CommetFeature::Portal(CommetPortalOptions {
            return_url: return_url.map(str::to_owned),
        }),
        CommetFeature::Subscriptions(CommetSubscriptionsOptions::default()),
        CommetFeature::Features,
        CommetFeature::Seats,
    ];
    let plugin = CommetPlugin::new(CommetOptions::new(client.clone(), features));
    let store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([91_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config.add_plugin(plugin).unwrap();
    let service = Arc::new(AuthService::try_new(store, config).unwrap());
    service
        .provision_password_user(NewPasswordUser {
            username: "commet_projection_owner".into(),
            name: "Commet Projection Owner".into(),
            email: Some("projection@example.test".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let session = service
        .sign_in_username(
            "commet_projection_owner",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    let cookie = format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(&session.token)
    );
    Fixture {
        app: lucid_auth::axum::router(service),
        client,
        cookie,
    }
}

pub(crate) async fn get(fixture: &Fixture, path: &str) -> (StatusCode, HeaderMap, Bytes) {
    send(fixture, Request::get(path).body(Body::empty()).unwrap()).await
}

pub(crate) async fn post(
    fixture: &Fixture,
    path: &str,
    body: Value,
) -> (StatusCode, HeaderMap, Bytes) {
    send(
        fixture,
        Request::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

async fn send(fixture: &Fixture, mut request: Request<Body>) -> (StatusCode, HeaderMap, Bytes) {
    request
        .headers_mut()
        .insert(header::HOST, "app.example.test".parse().unwrap());
    request
        .headers_mut()
        .insert(header::ORIGIN, "http://app.example.test".parse().unwrap());
    request
        .headers_mut()
        .insert(header::COOKIE, fixture.cookie.parse().unwrap());
    let response = fixture.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, bytes)
}
