#![allow(dead_code)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use http_body_util::BodyExt;
use lucid_auth::{AuthConfig, AuthService, MemoryStore, OneTimeTokenConfig, OneTimeTokenPlugin};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

pub const ORIGIN: &str = "http://localhost";

pub struct Fixture {
    pub app: Router,
    pub service: Arc<AuthService>,
    pub store: Arc<MemoryStore>,
}

pub struct Credential {
    pub cookie: String,
    pub token: String,
    pub session_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
}

pub fn fixture(one_time_token: OneTimeTokenConfig) -> Fixture {
    fixture_with(one_time_token, |_| {})
}

pub fn fixture_with(
    one_time_token: OneTimeTokenConfig,
    configure: impl FnOnce(&mut AuthConfig),
) -> Fixture {
    let mut config = AuthConfig::new([171_u8; 32]).unwrap();
    config.set_base_url(ORIGIN).unwrap();
    config.email_and_password.enabled = true;
    configure(&mut config);
    config
        .add_plugin(OneTimeTokenPlugin::new(one_time_token))
        .unwrap();
    let store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(store.clone(), config));
    Fixture {
        app: lucid_auth::axum::router(service.clone()),
        service,
        store,
    }
}

pub async fn signup(fixture: &Fixture, suffix: &str) -> Credential {
    let response = signup_response(&fixture.app, suffix).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = session_cookie(&response).expect("signup session cookie");
    let body = json_body(response).await;
    let token = body["token"].as_str().unwrap().to_owned();
    let session = fixture.service.session(&token).await.unwrap().unwrap();
    Credential {
        cookie,
        token,
        session_id: session.session.id,
        user_id: session.user.id,
    }
}

pub async fn signup_response(app: &Router, suffix: &str) -> Response {
    app.clone()
        .oneshot(
            Request::post("/api/auth/sign-up/email")
                .header(header::ORIGIN, ORIGIN)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name": "One-time token user",
                        "email": format!("ott-{suffix}@example.com"),
                        "password": "correct horse battery staple"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

pub async fn generate(app: &Router, cookie: Option<&str>) -> Response {
    let mut request = Request::get("/api/auth/one-time-token/generate");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

pub async fn verify(app: &Router, token: &str, cookie: Option<&str>) -> Response {
    verify_body(app, json!({ "token": token }), cookie).await
}

pub async fn verify_body(app: &Router, body: Value, cookie: Option<&str>) -> Response {
    let mut request = Request::post("/api/auth/one-time-token/verify")
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

pub async fn json_body(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

pub async fn generated_token(response: Response) -> String {
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await["token"]
        .as_str()
        .unwrap()
        .to_owned()
}

pub fn session_cookie(response: &Response) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("better-auth.session_token="))
        .map(|value| value.split(';').next().unwrap().to_owned())
}
