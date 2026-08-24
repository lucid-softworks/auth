use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, AuthStore, AuthUser, AuthorizationRequest, MemoryStore,
    OAuthAccountStore, OAuthTokens, OAuthUserInfo, SocialProvider,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use url::Url;

#[path = "social_oauth_contract/google.rs"]
mod google;
#[path = "social_oauth_contract/linking.rs"]
mod linking;

#[derive(Clone, Default)]
struct ProviderEvidence {
    authorization: Arc<Mutex<Option<AuthorizationRequest>>>,
    exchanges: Arc<Mutex<Vec<(String, String, String)>>>,
}

#[derive(Clone)]
struct FixtureProvider {
    evidence: ProviderEvidence,
    email_verified: bool,
}

#[async_trait]
impl SocialProvider for FixtureProvider {
    fn id(&self) -> &str {
        "fixture"
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
        false
    }

    fn require_email_verification(&self) -> bool {
        false
    }

    fn create_authorization_url(&self, request: &AuthorizationRequest) -> Result<Url, AuthError> {
        *self.evidence.authorization.lock().unwrap() = Some(request.clone());
        let challenge = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            Sha256::digest(request.code_verifier.as_bytes()),
        );
        let mut url = Url::parse("https://provider.fixture/authorize").unwrap();
        url.query_pairs_mut()
            .append_pair("client_id", "fixture-client")
            .append_pair("redirect_uri", &request.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("state", &request.state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("nonce", request.id_token_nonce.as_deref().unwrap());
        for (key, value) in &request.additional_params {
            url.query_pairs_mut().append_pair(key, value);
        }
        Ok(url)
    }

    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
        _device_id: Option<&str>,
    ) -> Result<OAuthTokens, AuthError> {
        if code != "valid-code" || code_verifier.len() != 128 {
            return Err(AuthError::OAuthInvalidCode);
        }
        self.evidence.exchanges.lock().unwrap().push((
            code.into(),
            code_verifier.into(),
            redirect_uri.into(),
        ));
        Ok(OAuthTokens {
            access_token: Some("access-secret".into()),
            refresh_token: Some("refresh-secret".into()),
            scopes: vec!["openid".into(), "email".into()],
            ..OAuthTokens::default()
        })
    }

    async fn get_user_info(
        &self,
        _tokens: &OAuthTokens,
        expected_nonce: Option<&str>,
        _provider_user: Option<&Value>,
    ) -> Result<OAuthUserInfo, AuthError> {
        let authorization = self.evidence.authorization.lock().unwrap();
        let expected = authorization
            .as_ref()
            .and_then(|request| request.id_token_nonce.as_deref());
        if expected_nonce != expected || expected_nonce.is_none() {
            return Err(AuthError::OAuthInvalidToken);
        }
        Ok(OAuthUserInfo {
            account_id: "subject-123".into(),
            issuer: "https://issuer.fixture".into(),
            name: "OAuth Casey".into(),
            email: "oauth.casey@example.com".into(),
            email_verified: self.email_verified,
            image: Some("https://provider.fixture/avatar.png".into()),
            additional_fields: serde_json::Map::new(),
            profile: serde_json::Map::new(),
        })
    }
}

fn application() -> (Router, Arc<MemoryStore>, ProviderEvidence) {
    application_with_policy(true, false)
}

fn application_with_policy(
    provider_email_verified: bool,
    trusted: bool,
) -> (Router, Arc<MemoryStore>, ProviderEvidence) {
    let evidence = ProviderEvidence::default();
    let provider = FixtureProvider {
        evidence: evidence.clone(),
        email_verified: provider_email_verified,
    };
    let mut config = AuthConfig::new([83_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    config.trust_origin("http://localhost").unwrap();
    config.account.encrypt_oauth_tokens = true;
    config.add_social_provider(provider).unwrap();
    if trusted {
        config.trust_social_provider("fixture").unwrap();
    }
    let store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(store.clone(), config));
    (lucid_auth::axum::router(service), store, evidence)
}

async fn insert_local_email_owner(store: &MemoryStore, email_verified: bool) {
    let now = chrono::Utc::now();
    store
        .create_user_without_account(AuthUser {
            id: uuid::Uuid::new_v4(),
            username: None,
            display_username: None,
            name: "Existing Local User".into(),
            email: "oauth.casey@example.com".into(),
            email_verified,
            image: None,
            additional_fields: serde_json::Map::new(),
            role: "user".into(),
            is_anonymous: false,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
}

async fn begin(app: &Router) -> (String, String, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/social")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost")
                .body(Body::from(
                    json!({
                        "provider": "fixture",
                        "callbackURL": "/dashboard",
                        "newUserCallbackURL": "/welcome",
                        "errorCallbackURL": "http://localhost/oauth-error?source=test",
                        "additionalParams": { "prompt": "consent" }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let url = Url::parse(body["url"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    (cookie, state, body)
}

#[tokio::test]
async fn social_redirect_and_callback_are_cookie_bound_one_time_and_encrypted() {
    let (app, store, evidence) = application();
    let (cookie, state, body) = begin(&app).await;
    assert_authorization(&body, &evidence);

    let callback = format!(
        "/api/auth/callback/fixture?code=valid-code&state={state}&iss=https%3A%2F%2Fissuer.fixture"
    );
    let response = app
        .clone()
        .oneshot(
            Request::get(&callback)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()[header::LOCATION], "/welcome");
    assert_session_cookies(response.headers());
    assert_encrypted_account(&store).await;
    assert_eq!(evidence.exchanges.lock().unwrap().len(), 1);

    let replay = app
        .clone()
        .oneshot(
            Request::get(&callback)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::FOUND);
    assert_eq!(
        replay.headers()[header::LOCATION],
        "http://localhost/api/auth/error?error=state_mismatch"
    );
    assert_eq!(evidence.exchanges.lock().unwrap().len(), 1);
}

fn assert_authorization(body: &Value, evidence: &ProviderEvidence) {
    let url = Url::parse(body["url"].as_str().unwrap()).unwrap();
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "prompt")
            .unwrap()
            .1,
        "consent"
    );
    let authorization = evidence.authorization.lock().unwrap().clone().unwrap();
    assert_eq!(
        authorization.redirect_uri,
        "http://localhost/api/auth/callback/fixture"
    );
    assert_eq!(authorization.code_verifier.len(), 128);
    assert!(authorization.id_token_nonce.is_some());
}

fn assert_session_cookies(headers: &axum::http::HeaderMap) {
    let cookies: Vec<_> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.starts_with("better-auth.session_token="))
    );
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.starts_with("better-auth.state=;"))
    );
}

async fn assert_encrypted_account(store: &MemoryStore) {
    let owner = store
        .find_oauth_account_owner("https://issuer.fixture", "subject-123")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.account.provider_id, "fixture");
    assert_eq!(owner.account.scope.as_deref(), Some("openid,email"));
    assert!(
        owner
            .account
            .access_token
            .as_deref()
            .unwrap()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    );
    assert_ne!(owner.account.access_token.as_deref(), Some("access-secret"));
}

#[tokio::test]
async fn callback_rejects_cookie_issuer_and_reserved_parameter_attacks() {
    let (app, _, evidence) = application();
    let (_, state, _) = begin(&app).await;
    let missing_cookie = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/auth/callback/fixture?code=valid-code&state={state}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        missing_cookie.headers()[header::LOCATION],
        "http://localhost/oauth-error?source=test&error=state_mismatch"
    );
    assert!(evidence.exchanges.lock().unwrap().is_empty());

    let (cookie, state, _) = begin(&app).await;
    let issuer_attack = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/auth/callback/fixture?code=valid-code&state={state}&iss=https%3A%2F%2Fevil.example"
            ))
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        issuer_attack.headers()[header::LOCATION],
        "http://localhost/oauth-error?source=test&error=issuer_mismatch"
    );
    assert!(evidence.exchanges.lock().unwrap().is_empty());

    let reserved = app
        .oneshot(
            Request::post("/api/auth/sign-in/social")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost")
                .body(Body::from(
                    json!({
                        "provider": "fixture",
                        "additionalParams": { "state": "attacker-controlled" }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reserved.status(), StatusCode::BAD_REQUEST);
}
