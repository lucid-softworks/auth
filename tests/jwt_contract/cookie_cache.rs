use super::support::{ORIGIN, decode_segment};
use axum::{Router, body::Body, http::Request};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, CookieCacheStrategy, JwtAdapterContext, JwtConfig, JwtPlugin,
    JwtSession, MemoryStore,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;

#[tokio::test]
async fn asymmetric_cookie_cache_uses_the_better_auth_bound_jwt_profile() {
    let (service, app) = fixture();
    let signup = request(
        &app,
        Request::post("/api/auth/sign-up/email")
            .header("origin", ORIGIN)
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "name": "Cached JWT User",
                    "email": "jwt-cache@example.com",
                    "password": "correct horse battery staple"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    let opaque = signup.body["token"].as_str().unwrap();
    let user_id = signup.body["user"]["id"].as_str().unwrap();
    let cache = signup.cookies["better-auth.session_data"].clone();
    let header = decode_segment(&cache, 0);
    let payload = decode_segment(&cache, 1);
    assert_eq!(header["typ"], "better-auth.session-cache+jwt");
    assert_eq!(header["alg"], "EdDSA");
    assert!(
        header["kid"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert_eq!(payload["iss"], ORIGIN);
    assert_eq!(payload["aud"], "better-auth:session-cache");
    assert_eq!(payload["sub"], user_id);
    assert_eq!(payload["sid"], opaque);
    assert_eq!(payload["session"]["token"], opaque);
    assert_eq!(payload["user"]["id"], user_id);
    assert!(payload["exp"].as_i64().unwrap() > payload["iat"].as_i64().unwrap());
    assert!(
        service
            .jwt()
            .unwrap()
            .verify_jwt(&JwtAdapterContext::default(), &cache, None)
            .await
            .unwrap()
            .is_none(),
        "the cache profile is not a normal service JWT"
    );
    let service_token = service
        .jwt()
        .unwrap()
        .get_jwt_token(
            &JwtAdapterContext::default(),
            &JwtSession {
                user: payload["user"].clone(),
                session: payload["session"].clone(),
            },
        )
        .await
        .unwrap();

    service.sign_out(opaque).await.unwrap();
    let cached = get_session(&app, &signup.cookies).await;
    assert_eq!(cached.body["user"]["id"], user_id);

    let mut tampered = signup.cookies.clone();
    let mut bytes = cache.into_bytes();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
    tampered.insert(
        "better-auth.session_data".into(),
        String::from_utf8(bytes).unwrap(),
    );
    assert_eq!(get_session(&app, &tampered).await.body, Value::Null);

    tampered.insert("better-auth.session_data".into(), service_token);
    assert_eq!(get_session(&app, &tampered).await.body, Value::Null);
}

#[test]
fn asymmetric_cookie_cache_requires_the_jwt_strategy_and_local_signer() {
    let mut config = AuthConfig::new([163_u8; 32]).unwrap();
    let mut jwt = JwtConfig {
        session_cookie_cache: true,
        ..JwtConfig::default()
    };
    config.add_plugin(JwtPlugin::new(jwt.clone())).unwrap();
    let error = match AuthService::try_new(Arc::new(MemoryStore::default()), config) {
        Ok(_) => panic!("non-JWT cookie strategy must be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("strategy"));

    jwt.jwt.sign = Some(Arc::new(RejectingSigner));
    jwt.jwks.remote_url = Some("https://issuer.example/jwks.json".into());
    jwt.jwks.key_pair_config = Some(lucid_auth::JwkAlgorithm::EdDsa);
    let mut config = AuthConfig::new([164_u8; 32]).unwrap();
    config.session.cookie_cache.strategy = CookieCacheStrategy::Jwt;
    config.add_plugin(JwtPlugin::new(jwt)).unwrap();
    let error = match AuthService::try_new(Arc::new(MemoryStore::default()), config) {
        Ok(_) => panic!("remote signing must be rejected for an asymmetric cookie cache"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("locally managed"));
}

fn fixture() -> (Arc<AuthService>, Router) {
    let mut config = AuthConfig::new([162_u8; 32]).unwrap();
    config.set_base_url(ORIGIN).unwrap();
    config.email_and_password.enabled = true;
    config.session.cookie_cache.enabled = true;
    config.session.cookie_cache.strategy = CookieCacheStrategy::Jwt;
    config
        .add_plugin(JwtPlugin::new(JwtConfig {
            session_cookie_cache: true,
            ..JwtConfig::default()
        }))
        .unwrap();
    let service = Arc::new(AuthService::new(Arc::new(MemoryStore::default()), config));
    (service.clone(), lucid_auth::axum::router(service))
}

struct HttpResult {
    body: Value,
    cookies: BTreeMap<String, String>,
}

async fn get_session(app: &Router, cookies: &BTreeMap<String, String>) -> HttpResult {
    let cookie = cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    request(
        app,
        Request::get("/api/auth/get-session")
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

async fn request(app: &Router, request: Request<Body>) -> HttpResult {
    let response = app.clone().oneshot(request).await.unwrap();
    let cookies = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok()?.split(';').next()?.split_once('='))
        .map(|(name, value)| (name.into(), value.into()))
        .collect();
    let body =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    HttpResult { body, cookies }
}

struct RejectingSigner;

#[async_trait::async_trait]
impl lucid_auth::JwtRemoteSigner for RejectingSigner {
    async fn sign(
        &self,
        _: serde_json::Map<String, Value>,
        _: Option<lucid_auth::JwtProtectedHeader>,
        _: Option<lucid_auth::JwtSigningOverrides>,
    ) -> Result<String, lucid_auth::AuthError> {
        unreachable!()
    }
}
