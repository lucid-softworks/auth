#![allow(dead_code)]

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, JwkAlgorithm, JwtAdapterConfig, JwtAdapterContext,
    JwtConfig, JwtJwkCreator, JwtJwksReader, JwtPlugin, JwtSession, MemoryStore, NewJwk, StoredJwk,
};
use serde_json::{Map, Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Mutex;
use tower::ServiceExt;

pub const ORIGIN: &str = "http://localhost";

pub struct Fixture {
    pub app: Router,
    pub service: Arc<AuthService>,
    pub store: Arc<MemoryStore>,
}

pub struct SessionCredential {
    pub cookie: String,
    pub opaque: String,
    pub user_id: String,
}

pub fn fixture(jwt: JwtConfig) -> Fixture {
    let mut config = AuthConfig::new([161_u8; 32]).unwrap();
    config.set_base_url(ORIGIN).unwrap();
    config.email_and_password.enabled = true;
    config.add_plugin(JwtPlugin::new(jwt)).unwrap();
    let store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(store.clone(), config));
    Fixture {
        app: lucid_auth::axum::router(service.clone()),
        service,
        store,
    }
}

pub fn algorithm_config(algorithm: JwkAlgorithm) -> JwtConfig {
    let mut config = JwtConfig::default();
    config.jwks.key_pair_config = Some(algorithm);
    config
}

pub async fn signup(fixture: &Fixture, suffix: &str) -> SessionCredential {
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-up/email")
                .header(header::ORIGIN, ORIGIN)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name": "JWT User",
                        "email": format!("jwt-{suffix}@example.com"),
                        "password": "correct horse battery staple"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("better-auth.session_token="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let body = json_body(response).await;
    SessionCredential {
        cookie,
        opaque: body["token"].as_str().unwrap().to_owned(),
        user_id: body["user"]["id"].as_str().unwrap().to_owned(),
    }
}

pub async fn get(app: &Router, path: &str, cookie: Option<&str>) -> Response {
    let mut request = Request::get(path);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

pub async fn json_body(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

pub async fn token(fixture: &Fixture, cookie: &str) -> String {
    let response = get(&fixture.app, "/api/auth/token", Some(cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await["token"]
        .as_str()
        .unwrap()
        .to_owned()
}

pub fn decode_segment(token: &str, index: usize) -> Value {
    let segment = token.split('.').nth(index).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).unwrap()).unwrap()
}

pub fn token_header(token: &str) -> Value {
    decode_segment(token, 0)
}

pub fn token_payload(token: &str) -> Value {
    decode_segment(token, 1)
}

pub fn jwt_session(user_id: &str) -> JwtSession {
    JwtSession {
        user: json!({
            "id": user_id,
            "name": "JWT User",
            "email": "jwt-service@example.com",
            "emailVerified": true,
            "custom": "user-claim"
        }),
        session: json!({
            "id": "018f0000-0000-7000-8000-000000000020",
            "userId": user_id,
            "token": "opaque-session-token"
        }),
    }
}

pub fn payload(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Map<String, Value> {
    entries
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
}

#[derive(Default)]
pub struct RecordingAdapter {
    pub keys: Mutex<Vec<StoredJwk>>,
    pub reads: Mutex<Vec<JwtAdapterContext>>,
    pub creates: Mutex<Vec<JwtAdapterContext>>,
    next_id: AtomicUsize,
}

impl RecordingAdapter {
    pub fn config(self: &Arc<Self>) -> JwtAdapterConfig {
        JwtAdapterConfig {
            get_jwks: Some(self.clone()),
            create_jwk: Some(self.clone()),
        }
    }
}

#[async_trait]
impl JwtJwksReader for RecordingAdapter {
    async fn get_jwks(
        &self,
        context: &JwtAdapterContext,
    ) -> Result<Option<Vec<StoredJwk>>, AuthError> {
        self.reads.lock().await.push(context.clone());
        Ok(Some(self.keys.lock().await.clone()))
    }
}

#[async_trait]
impl JwtJwkCreator for RecordingAdapter {
    async fn create_jwk(
        &self,
        data: NewJwk,
        context: &JwtAdapterContext,
    ) -> Result<StoredJwk, AuthError> {
        self.creates.lock().await.push(context.clone());
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let stored = StoredJwk {
            id: format!("recorded-{id}"),
            public_key: data.public_key,
            private_key: data.private_key,
            created_at: data.created_at,
            expires_at: data.expires_at,
            alg: data.alg,
            crv: data.crv,
        };
        self.keys.lock().await.push(stored.clone());
        Ok(stored)
    }
}
