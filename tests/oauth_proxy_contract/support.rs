#![allow(dead_code)]

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, header},
    response::Response,
};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, AuthorizationRequest, MemoryStore, OAuthProxyConfig,
    OAuthProxyPlugin, OAuthTokens, OAuthUserInfo, SocialProvider,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use url::Url;

pub(super) const PREVIEW_ORIGIN: &str = "https://preview.example.test";
pub(super) const PRODUCTION_ORIGIN: &str = "https://auth.example.test";
pub(super) const APP_ORIGIN: &str = "https://app.example.test";
pub(super) const PROXY_SECRET: &[u8] = b"PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP";

pub(super) struct Fixture {
    pub(super) app: Router,
    pub(super) service: Arc<AuthService>,
    pub(super) store: Arc<MemoryStore>,
    pub(super) evidence: ProviderEvidence,
}

pub(super) fn fixture(origin: &str, global_secret: u8, proxy: OAuthProxyConfig) -> Fixture {
    fixture_with(origin, global_secret, proxy, |_| {})
}

pub(super) fn fixture_with(
    origin: &str,
    global_secret: u8,
    proxy: OAuthProxyConfig,
    configure: impl FnOnce(&mut AuthConfig),
) -> Fixture {
    let evidence = ProviderEvidence::default();
    let mut config = AuthConfig::new([global_secret; 32]).unwrap();
    config.set_base_url(origin).unwrap();
    for trusted in [PREVIEW_ORIGIN, PRODUCTION_ORIGIN, APP_ORIGIN] {
        config.trust_origin(trusted).unwrap();
    }
    configure(&mut config);
    config
        .add_social_provider(FixtureProvider::new(evidence.clone()))
        .unwrap();
    config.add_plugin(OAuthProxyPlugin::new(proxy)).unwrap();
    let store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(store.clone(), config));
    Fixture {
        app: lucid_auth::axum::router(service.clone()),
        service,
        store,
        evidence,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExchangeEvidence {
    pub(super) code: String,
    pub(super) code_verifier: String,
    pub(super) redirect_uri: String,
    pub(super) device_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct UserInfoEvidence {
    pub(super) expected_nonce: Option<String>,
    pub(super) provider_user: Option<Value>,
}

#[derive(Clone, Default)]
pub(super) struct ProviderEvidence {
    authorization: Arc<Mutex<Vec<AuthorizationRequest>>>,
    exchanges: Arc<Mutex<Vec<ExchangeEvidence>>>,
    user_info: Arc<Mutex<Vec<UserInfoEvidence>>>,
}

impl ProviderEvidence {
    pub(super) fn authorization(&self) -> Vec<AuthorizationRequest> {
        self.authorization.lock().unwrap().clone()
    }

    pub(super) fn exchanges(&self) -> Vec<ExchangeEvidence> {
        self.exchanges.lock().unwrap().clone()
    }

    pub(super) fn user_info(&self) -> Vec<UserInfoEvidence> {
        self.user_info.lock().unwrap().clone()
    }
}

#[derive(Clone)]
pub(super) struct FixtureProvider {
    evidence: ProviderEvidence,
    provider_id: &'static str,
    disable_sign_up: bool,
}

impl FixtureProvider {
    pub(super) fn new(evidence: ProviderEvidence) -> Self {
        Self {
            evidence,
            provider_id: "fixture",
            disable_sign_up: false,
        }
    }

    pub(super) fn with_disable_sign_up(mut self) -> Self {
        self.disable_sign_up = true;
        self
    }
}

#[async_trait]
impl SocialProvider for FixtureProvider {
    fn id(&self) -> &str {
        self.provider_id
    }

    fn issuer(&self) -> Option<&str> {
        Some("https://issuer.fixture")
    }

    fn requires_id_token_nonce(&self) -> bool {
        true
    }

    fn disable_implicit_sign_up(&self) -> bool {
        false
    }

    fn disable_sign_up(&self) -> bool {
        self.disable_sign_up
    }

    fn require_email_verification(&self) -> bool {
        false
    }

    fn create_authorization_url(&self, request: &AuthorizationRequest) -> Result<Url, AuthError> {
        self.evidence
            .authorization
            .lock()
            .unwrap()
            .push(request.clone());
        let mut url = Url::parse("https://provider.fixture/authorize").unwrap();
        url.query_pairs_mut()
            .append_pair("state", &request.state)
            .append_pair("redirect_uri", &request.redirect_uri)
            .append_pair("code_challenge", &request.code_verifier);
        if let Some(nonce) = &request.id_token_nonce {
            url.query_pairs_mut().append_pair("nonce", nonce);
        }
        Ok(url)
    }

    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
        device_id: Option<&str>,
    ) -> Result<OAuthTokens, AuthError> {
        if code != "valid-code" || code_verifier.len() != 128 {
            return Err(AuthError::OAuthInvalidCode);
        }
        self.evidence
            .exchanges
            .lock()
            .unwrap()
            .push(ExchangeEvidence {
                code: code.into(),
                code_verifier: code_verifier.into(),
                redirect_uri: redirect_uri.into(),
                device_id: device_id.map(str::to_owned),
            });
        Ok(OAuthTokens {
            access_token: Some("proxy-access-token".into()),
            refresh_token: Some("proxy-refresh-token".into()),
            id_token: Some("proxy-id-token".into()),
            scopes: vec!["openid".into(), "email".into()],
            ..OAuthTokens::default()
        })
    }

    async fn get_user_info(
        &self,
        _tokens: &OAuthTokens,
        expected_nonce: Option<&str>,
        provider_user: Option<&Value>,
    ) -> Result<OAuthUserInfo, AuthError> {
        self.evidence
            .user_info
            .lock()
            .unwrap()
            .push(UserInfoEvidence {
                expected_nonce: expected_nonce.map(str::to_owned),
                provider_user: provider_user.cloned(),
            });
        Ok(OAuthUserInfo {
            account_id: "proxy-subject".into(),
            issuer: "https://issuer.fixture".into(),
            name: "Proxy User".into(),
            email: "proxy@example.com".into(),
            email_verified: true,
            image: Some("https://provider.fixture/avatar.png".into()),
            additional_fields: serde_json::Map::new(),
            profile: serde_json::Map::from_iter([(
                "rawClaim".into(),
                Value::String("preserved".into()),
            )]),
        })
    }
}

pub(super) async fn send(app: &Router, request: Request<Body>) -> Response {
    app.clone().oneshot(request).await.unwrap()
}

pub(super) fn set_cookies(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect()
}

pub(super) fn cookie_header(cookies: &[String]) -> String {
    cookies
        .iter()
        .map(|cookie| cookie.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}

pub(super) async fn response_text(response: Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

pub(super) async fn response_json(response: Response) -> Value {
    serde_json::from_str(&response_text(response).await).unwrap()
}

pub(super) fn query_value(url: &str, name: &str) -> String {
    Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == name)
        .unwrap()
        .1
        .into_owned()
}

pub(super) fn decrypt_json(secret: &[u8], encoded: &str) -> Value {
    let envelope = hex::decode(encoded).unwrap();
    let (nonce, ciphertext) = envelope.split_at(24);
    let key = Sha256::digest(secret);
    let plaintext = XChaCha20Poly1305::new_from_slice(&key)
        .unwrap()
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .unwrap();
    serde_json::from_slice(&plaintext).unwrap()
}

pub(super) fn encrypt_json(secret: &[u8], value: &Value) -> String {
    let nonce = [79_u8; 24];
    let key = Sha256::digest(secret);
    let ciphertext = XChaCha20Poly1305::new_from_slice(&key)
        .unwrap()
        .encrypt(XNonce::from_slice(&nonce), value.to_string().as_bytes())
        .unwrap();
    hex::encode([nonce.as_slice(), ciphertext.as_slice()].concat())
}
