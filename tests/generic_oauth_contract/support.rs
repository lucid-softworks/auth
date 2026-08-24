use axum::{
    Json, Router,
    body::{Body, Bytes},
    http::{HeaderMap, Request, StatusCode, header},
    routing::{get, post},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, GenericOAuthConfig, GenericOAuthPlugin, MemoryStore,
    OAuthAccountStore, OAuthStateStrategy,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use url::Url;

#[derive(Clone, Default)]
pub(crate) struct Evidence {
    pub(crate) token_forms: Arc<Mutex<Vec<String>>>,
    pub(crate) token_authorizations: Arc<Mutex<Vec<Option<String>>>>,
}

async fn token(
    axum::extract::State(evidence): axum::extract::State<Evidence>,
    headers: HeaderMap,
    body: Bytes,
) -> Json<Value> {
    evidence.token_authorizations.lock().unwrap().push(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    );
    evidence
        .token_forms
        .lock()
        .unwrap()
        .push(String::from_utf8(body.to_vec()).unwrap());
    Json(json!({
        "access_token": "access-secret",
        "refresh_token": "refresh-secret",
        "expires_in": 3600,
        "scope": ["profile", "email"]
    }))
}

async fn user_info(headers: HeaderMap) -> Json<Value> {
    assert_eq!(headers[header::AUTHORIZATION], "Bearer access-secret");
    Json(json!({
        "id": 42,
        "name": "Generic Casey",
        "email": "generic.casey@example.com",
        "email_verified": true,
        "picture": "https://provider.example/avatar.png"
    }))
}

pub(crate) async fn fixture() -> (String, Evidence, tokio::task::JoinHandle<()>) {
    let evidence = Evidence::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/token", post(token))
        .route("/userinfo", get(user_info))
        .with_state(evidence.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), evidence, server)
}

pub(crate) async fn oidc_fixture() -> (String, tokio::task::JoinHandle<()>) {
    async fn discovery(axum::extract::State(base): axum::extract::State<String>) -> Json<Value> {
        Json(json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": "/jwks",
            "id_token_signing_alg_values_supported": ["HS256"]
        }))
    }
    async fn jwks() -> Json<Value> {
        Json(json!({"keys":[{
            "kty":"oct",
            "kid":"generic-oidc",
            "alg":"HS256",
            "k":"c3VwZXItc2VjcmV0LXNpZ25pbmcta2V5LTMyYnl0ZXMh"
        }]}))
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/discovery", get(discovery))
        .route("/jwks", get(jwks))
        .with_state(base.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, server)
}

pub(crate) fn signed_id_token(issuer: &str, audience: &str, nonce: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some("generic-oidc".into());
    jsonwebtoken::encode(
        &header,
        &json!({
            "sub": "oidc-subject",
            "iss": issuer,
            "aud": audience,
            "iat": now,
            "exp": now + 3600,
            "nonce": nonce,
            "email": "oidc@example.com",
            "email_verified": true,
            "name": "OIDC User"
        }),
        &jsonwebtoken::EncodingKey::from_secret(b"super-secret-signing-key-32bytes!"),
    )
    .unwrap()
}

pub(crate) async fn application(
    strategy: OAuthStateStrategy,
) -> (
    Router,
    Arc<MemoryStore>,
    Evidence,
    tokio::task::JoinHandle<()>,
) {
    let (provider_base, evidence, server) = fixture().await;
    let mut provider = GenericOAuthConfig::new("acme", "acme-client");
    provider.name = Some("Acme Identity".into());
    provider.account_issuer = Some("https://identity.acme.example".into());
    provider.authorization_url = Some(format!("{provider_base}/authorize?existing=kept"));
    provider.token_url = Some(format!("{provider_base}/token"));
    provider.user_info_url = Some(format!("{provider_base}/userinfo"));
    provider.end_session_endpoint = Some(format!("{provider_base}/logout"));
    provider.allow_idp_initiated = true;
    provider.scopes = vec!["profile".into()];
    provider
        .authorization_url_params
        .insert("response_mode".into(), "form_post".into());
    let plugin = GenericOAuthPlugin::initialize(vec![provider])
        .await
        .unwrap();
    let mut config = AuthConfig::new([47_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    config.trust_origin("http://localhost").unwrap();
    config.account.store_state_strategy = strategy;
    config.add_plugin(plugin).unwrap();
    let store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(store.clone(), config));
    (lucid_auth::axum::router(service), store, evidence, server)
}

pub(crate) async fn begin_generic_flow(
    app: &Router,
    strategy: OAuthStateStrategy,
) -> (String, String) {
    let begin = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-in/social")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost")
                .body(Body::from(
                    json!({
                        "provider": "acme",
                        "callbackURL": "/dashboard",
                        "errorCallbackURL": "/oauth-error",
                        "scopes": ["email"],
                        "additionalParams": {
                            "response_mode": "query",
                            "audience": "api"
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(begin.status(), StatusCode::OK);
    let state_cookie = first_cookie(
        begin.headers(),
        match strategy {
            OAuthStateStrategy::Database => "better-auth.state",
            OAuthStateStrategy::Cookie => "better-auth.oauth_state",
        },
    );
    let body: Value =
        serde_json::from_slice(&begin.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let authorization = Url::parse(body["url"].as_str().unwrap()).unwrap();
    let query = authorization
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(query["scope"], "email profile");
    assert_eq!(query["response_mode"], "query");
    assert_eq!(query["audience"], "api");
    assert_eq!(query["existing"], "kept");
    assert_eq!(query["code_challenge_method"], "S256");
    (state_cookie, query["state"].to_string())
}

pub(crate) async fn assert_cookie_state_mismatch(app: &Router, state_cookie: &str) {
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/auth/callback/acme?code=valid-code&state=wrong-state")
                .header(header::COOKIE, state_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers()[header::LOCATION],
        "/oauth-error?error=state_mismatch"
    );
}

pub(crate) async fn finish_generic_flow(
    app: &Router,
    store: &MemoryStore,
    evidence: &Evidence,
    state_cookie: &str,
    state: &str,
) -> String {
    let callback_path = format!("/api/auth/callback/acme?code=valid-code&state={state}");
    let post_callback = app
        .clone()
        .oneshot(
            Request::post(&callback_path)
                .header(header::COOKIE, state_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post_callback.status(), StatusCode::FOUND);
    assert_eq!(
        post_callback.headers()[header::LOCATION],
        format!("http://localhost{callback_path}")
    );
    let callback = app
        .clone()
        .oneshot(
            Request::get(callback_path)
                .header(header::COOKIE, state_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::FOUND);
    assert_eq!(callback.headers()[header::LOCATION], "/dashboard");
    let session_cookie = cookie_with_prefix(callback.headers(), "better-auth.session_token");
    let owner = store
        .find_oauth_account_owner("https://identity.acme.example", "42")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.account.access_token.as_deref(), Some("access-secret"));
    assert_eq!(
        owner.account.refresh_token.as_deref(),
        Some("refresh-secret")
    );
    assert_eq!(owner.account.scope.as_deref(), Some("profile,email"));
    let form = evidence.token_forms.lock().unwrap()[0].clone();
    assert!(form.contains("code_verifier="));
    assert!(form.contains("client_id=acme-client"));
    session_cookie
}

pub(crate) async fn assert_generic_logout(app: &Router, session_cookie: &str) {
    let sign_out = app
        .clone()
        .oneshot(
            Request::post("/api/auth/sign-out")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "http://localhost")
                .header(header::COOKIE, session_cookie)
                .body(Body::from(
                    json!({"callbackURL": "/signed-out", "state": "logout-state"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sign_out.status(), StatusCode::OK);
    let location = sign_out.headers()[header::LOCATION].to_str().unwrap();
    let logout = Url::parse(location).unwrap();
    assert_eq!(logout.path(), "/logout");
    let query = logout
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        query["post_logout_redirect_uri"],
        "http://localhost/signed-out"
    );
    assert_eq!(query["client_id"], "acme-client");
    assert_eq!(query["state"], "logout-state");
}

fn first_cookie(headers: &HeaderMap, name: &str) -> String {
    cookie_with_prefix(headers, name)
}

fn cookie_with_prefix(headers: &HeaderMap, prefix: &str) -> String {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(prefix))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}
