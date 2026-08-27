use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, Response, header},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt as _;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, AuthorizationRequest, ElectronPlugin, MemoryStore,
    OAuthTokens, OAuthUserInfo, SocialProvider,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use url::Url;

static NEXT_EMAIL: AtomicUsize = AtomicUsize::new(1);

#[derive(Clone, Default)]
pub(super) struct ProviderEvidence(pub Arc<Mutex<Vec<AuthorizationRequest>>>);

#[derive(Clone)]
struct FixtureProvider(ProviderEvidence);

#[async_trait]
impl SocialProvider for FixtureProvider {
    fn id(&self) -> &str {
        "fixture"
    }
    fn issuer(&self) -> Option<&str> {
        Some("https://issuer.fixture")
    }
    fn requires_id_token_nonce(&self) -> bool {
        false
    }
    fn disable_implicit_sign_up(&self) -> bool {
        false
    }
    fn disable_sign_up(&self) -> bool {
        false
    }
    fn require_email_verification(&self) -> bool {
        false
    }

    fn create_authorization_url(&self, request: &AuthorizationRequest) -> Result<Url, AuthError> {
        self.0.0.lock().unwrap().push(request.clone());
        let mut url = Url::parse("https://provider.fixture/authorize").unwrap();
        url.query_pairs_mut().append_pair("state", &request.state);
        Ok(url)
    }

    async fn exchange_code(
        &self,
        _code: &str,
        _code_verifier: &str,
        _redirect_uri: &str,
        _device_id: Option<&str>,
    ) -> Result<OAuthTokens, AuthError> {
        Err(AuthError::OAuthInvalidCode)
    }

    async fn get_user_info(
        &self,
        _tokens: &OAuthTokens,
        _expected_nonce: Option<&str>,
        _provider_user: Option<&Value>,
    ) -> Result<OAuthUserInfo, AuthError> {
        Err(AuthError::OAuthInvalidToken)
    }
}

pub(super) fn application(
    enabled: bool,
    provider: bool,
) -> (Router, Arc<AuthService>, ProviderEvidence) {
    let evidence = ProviderEvidence::default();
    let mut config = AuthConfig::new([78; 32]).unwrap();
    config.set_base_url("http://localhost:3000").unwrap();
    config.trust_origin("http://localhost:3000").unwrap();
    config.trust_origin("myapp:/").unwrap();
    config.email_and_password.enabled = true;
    if provider {
        config
            .add_social_provider(FixtureProvider(evidence.clone()))
            .unwrap();
    }
    if enabled {
        config.add_plugin(ElectronPlugin::default()).unwrap();
    }
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    (lucid_auth::axum::router(service.clone()), service, evidence)
}

pub(super) fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub(super) fn sign_up_request(query: Option<&str>, origin: Option<(&str, &str)>) -> Request<Body> {
    let id = NEXT_EMAIL.fetch_add(1, Ordering::Relaxed);
    let uri = query.map_or_else(
        || "/api/auth/sign-up/email".to_owned(),
        |query| format!("/api/auth/sign-up/email?{query}"),
    );
    let mut request = Request::post(uri).header(header::CONTENT_TYPE, "application/json");
    if let Some((name, value)) = origin {
        request = request.header(name, value);
    }
    request
        .body(Body::from(
            json!({
                "email": format!("electron-{id}@example.com"),
                "password": "correct horse battery staple",
                "name": "Electron User"
            })
            .to_string(),
        ))
        .unwrap()
}

pub(super) async fn body_json(response: Response<Body>) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

pub(super) fn set_cookies(response: &Response<Body>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect()
}

pub(super) fn cookie_value(cookies: &[String], name: &str) -> Option<String> {
    cookies.iter().rev().find_map(|cookie| {
        cookie
            .strip_prefix(&format!("{name}="))
            .and_then(|value| value.split(';').next())
            .map(str::to_owned)
    })
}

pub(super) fn cookie_header(cookies: &[String]) -> String {
    cookies
        .iter()
        .filter_map(|cookie| cookie.split(';').next())
        .collect::<Vec<_>>()
        .join("; ")
}
