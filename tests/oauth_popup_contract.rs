use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, AuthorizationRequest, MemoryStore, OAuthPopupPlugin,
    OAuthTokens, OAuthUserInfo, SocialProvider,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use url::Url;

#[derive(Clone, Default)]
struct Evidence(Arc<Mutex<Option<AuthorizationRequest>>>);

#[derive(Clone)]
struct FixtureProvider(Evidence);

#[async_trait]
impl SocialProvider for FixtureProvider {
    fn id(&self) -> &str {
        "fixture"
    }

    fn issuer(&self) -> Option<&str> {
        Some("fixture")
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
        *self.0.0.lock().unwrap() = Some(request.clone());
        let mut url = Url::parse("https://provider.example/authorize").unwrap();
        url.query_pairs_mut()
            .append_pair("state", &request.state)
            .append_pair("redirect_uri", &request.redirect_uri)
            .append_pair("code_challenge", &request.code_verifier);
        Ok(url)
    }

    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        _redirect_uri: &str,
        _device_id: Option<&str>,
    ) -> Result<OAuthTokens, AuthError> {
        if code != "valid" || code_verifier.len() != 128 {
            return Err(AuthError::OAuthInvalidCode);
        }
        Ok(OAuthTokens {
            access_token: Some("access".into()),
            ..OAuthTokens::default()
        })
    }

    async fn get_user_info(
        &self,
        _tokens: &OAuthTokens,
        expected_nonce: Option<&str>,
        _provider_user: Option<&Value>,
    ) -> Result<OAuthUserInfo, AuthError> {
        if expected_nonce.is_none() {
            return Err(AuthError::OAuthInvalidToken);
        }
        Ok(OAuthUserInfo {
            account_id: "popup-user".into(),
            issuer: "fixture".into(),
            name: "Popup User".into(),
            email: "popup@example.com".into(),
            email_verified: true,
            image: None,
            additional_fields: serde_json::Map::new(),
            profile: serde_json::Map::new(),
        })
    }
}

fn application(with_plugin: bool) -> (Router, Evidence) {
    let evidence = Evidence::default();
    let mut config = AuthConfig::new([154_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    config.trust_origin("https://app.example").unwrap();
    config
        .add_social_provider(FixtureProvider(evidence.clone()))
        .unwrap();
    if with_plugin {
        config.add_plugin(OAuthPopupPlugin).unwrap();
    }
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    (lucid_auth::axum::router(service), evidence)
}

async fn request(app: &Router, uri: &str, cookie: Option<&str>) -> axum::response::Response {
    let mut request = Request::get(uri).body(Body::empty()).unwrap();
    if let Some(cookie) = cookie {
        request
            .headers_mut()
            .insert(header::COOKIE, cookie.parse().unwrap());
    }
    app.clone().oneshot(request).await.unwrap()
}

fn cookies(response: &axum::response::Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect()
}

fn cookie_header(set_cookies: &[String]) -> String {
    set_cookies
        .iter()
        .map(|cookie| cookie.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}

async fn body(response: axum::response::Response) -> String {
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

#[tokio::test]
async fn plugin_is_optional_and_declares_only_the_pinned_surface() {
    let (app, _) = application(false);
    assert_eq!(
        request(
            &app,
            "/api/auth/oauth-popup/start?provider=fixture&popupOrigin=https%3A%2F%2Fapp.example",
            None,
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );

    let mut config = AuthConfig::new([155_u8; 32]).unwrap();
    config.add_plugin(OAuthPopupPlugin).unwrap();
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);
    let descriptor = service
        .plugin_metadata()
        .iter()
        .find(|plugin| plugin.id == "oauth-popup")
        .unwrap();
    assert_eq!(descriptor.endpoints[0].path, "/oauth-popup/start");
    assert_eq!(descriptor.endpoints[0].client_method, "signIn.popup");
    assert_eq!(descriptor.client.unwrap().factory, "oauthPopupClient");
    assert_eq!(descriptor.cookies[0].name, "better-auth.oauth_popup");
    assert!(descriptor.dependencies.is_empty());
    assert!(descriptor.rate_limits.is_empty());
}

#[tokio::test]
async fn validation_origin_redirect_and_provider_order_match() {
    let (app, _) = application(true);
    let response = request(&app, "/api/auth/oauth-popup/start", None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(body(response).await.contains("VALIDATION_ERROR"));

    let response = request(
        &app,
        "/api/auth/oauth-popup/start?provider=missing&popupOrigin=https%3A%2F%2Fevil.example&callbackURL=https%3A%2F%2Fevil.example%2Fafter",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        serde_json::from_str::<Value>(&body(response).await).unwrap(),
        json!({"code":"INVALID_ORIGIN","message":"Invalid origin"})
    );

    let response = request(
        &app,
        "/api/auth/oauth-popup/start?provider=missing&popupOrigin=https%3A%2F%2Fapp.example&popupNonce=n&callbackURL=https%3A%2F%2Fevil.example%2Fafter",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body(response).await;
    assert!(html.contains("invalid_callback_url"));
    assert!(html.contains("Untrusted URL: https://evil.example/after"));

    let response = request(
        &app,
        "/api/auth/oauth-popup/start?provider=missing&popupOrigin=https%3A%2F%2Fapp.example&popupNonce=n",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(body(response).await.contains("provider_not_found"));
}

#[tokio::test]
async fn start_and_callback_emit_the_exact_popup_protocol() {
    let (app, evidence) = application(true);
    let start = request(
        &app,
        "/api/auth/oauth-popup/start?provider=fixture&popupOrigin=https%3A%2F%2Fapp.example&popupNonce=nonce-1&callbackURL=%2Fdashboard&scopes=openid%2C%2Cemail&requestSignUp=true&additionalData=%7B%22provider%22%3A%22kept%22%2C%22callbackURL%22%3A%22dropped%22%7D",
        None,
    )
    .await;
    assert_eq!(start.status(), StatusCode::FOUND);
    let location = Url::parse(start.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let state = location
        .query_pairs()
        .find(|(name, _)| name == "state")
        .unwrap()
        .1
        .into_owned();
    let set_cookies = cookies(&start);
    assert_eq!(set_cookies.len(), 2);
    assert!(set_cookies[0].starts_with("better-auth.state="));
    assert!(set_cookies[1].starts_with("better-auth.oauth_popup="));
    assert!(set_cookies[1].contains("Max-Age=600"));
    let authorization = evidence.0.lock().unwrap().clone().unwrap();
    assert_eq!(authorization.code_verifier.len(), 128);
    assert_eq!(authorization.scopes.unwrap(), vec!["openid", "", "email"]);

    let callback = request(
        &app,
        &format!("/api/auth/callback/fixture?code=valid&state={state}"),
        Some(&cookie_header(&set_cookies)),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::OK);
    assert_eq!(
        callback.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    assert_eq!(callback.headers()[header::LOCATION], "/dashboard");
    assert!(
        callback.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("sha256-tIo2K8VBC9SnhvdZ+9GsGkQoZm+jm/JcxL+d+i8b8KQ=")
    );
    let callback_cookies = cookies(&callback);
    assert!(
        callback_cookies
            .iter()
            .any(|cookie| cookie.starts_with("better-auth.session_token="))
    );
    assert!(callback_cookies.iter().any(|cookie| {
        cookie.starts_with("better-auth.oauth_popup=") && cookie.contains("Max-Age=0")
    }));
    let html = body(callback).await;
    assert!(html.contains("\"type\":\"better-auth:oauth-popup\""));
    assert!(html.contains("\"targetOrigin\":\"https://app.example\""));
    assert!(html.contains("\"nonce\":\"nonce-1\""));
    assert!(html.contains("\"redirectTo\":\"/dashboard\""));
    assert!(html.contains("better-auth-oauth-popup"));
}

#[tokio::test]
async fn missing_or_invalid_marker_is_a_callback_noop() {
    let (app, _) = application(true);
    let response = request(
        &app,
        "/api/auth/callback/fixture?error=denied&state=missing",
        Some("better-auth.oauth_popup=invalid.signature"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(!cookies(&response).iter().any(|cookie| {
        cookie.starts_with("better-auth.oauth_popup=") && cookie.contains("Max-Age=0")
    }));
}
