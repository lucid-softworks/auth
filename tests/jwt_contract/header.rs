use super::support::{Fixture, ORIGIN, fixture, get, json_body, signup};
use async_trait::async_trait;
use axum::{
    http::{HeaderValue, header},
    response::Response,
};
use lucid_auth::{
    AuthConfig, AuthError, AuthPlugin, AuthService, JwkAlgorithm, JwtConfig, JwtPlugin,
    JwtProtectedHeader, JwtRemoteSigner, JwtSigningOverrides, MemoryStore, PluginDescriptor,
    PluginRequestContext,
};
use serde_json::{Map, Value};
use std::sync::Arc;

struct ExistingExposeHeader;

#[async_trait]
impl AuthPlugin for ExistingExposeHeader {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "jwt-header-fixture",
            display_name: "JWT header fixture",
            version: "1.7.1",
            provenance: lucid_auth::PluginProvenance::lucid_extension(),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(&[]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    async fn after_response(
        &self,
        _service: &AuthService,
        request: &PluginRequestContext,
        mut response: Response,
    ) -> Response {
        if request.path == "/get-session" {
            response.headers_mut().insert(
                header::ACCESS_CONTROL_EXPOSE_HEADERS,
                HeaderValue::from_static("X-First, Set-Auth-Jwt"),
            );
        }
        response
    }

    fn contributes_on_response(&self) -> bool {
        true
    }
}

fn fixture_with_expose_header(jwt: JwtConfig) -> Fixture {
    let mut config = AuthConfig::new([164_u8; 32]).unwrap();
    config.set_base_url(ORIGIN).unwrap();
    config.email_and_password.enabled = true;
    config.add_plugin(ExistingExposeHeader).unwrap();
    config.add_plugin(JwtPlugin::new(jwt)).unwrap();
    let store = Arc::new(MemoryStore::default());
    let service = Arc::new(AuthService::new(store.clone(), config));
    Fixture {
        app: lucid_auth::axum::router(service.clone()),
        service,
        store,
    }
}

struct FailingSigner;

#[async_trait]
impl JwtRemoteSigner for FailingSigner {
    async fn sign(
        &self,
        _payload: Map<String, Value>,
        _header: Option<JwtProtectedHeader>,
        _signing: Option<JwtSigningOverrides>,
    ) -> Result<String, AuthError> {
        Err(AuthError::Storage("remote signer unavailable".into()))
    }
}

#[tokio::test]
async fn valid_get_session_sets_and_merges_header_but_null_session_does_not() {
    let fixture = fixture_with_expose_header(JwtConfig::default());
    let credential = signup(&fixture, "header").await;
    let response = get(
        &fixture.app,
        "/api/auth/get-session",
        Some(&credential.cookie),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert!(
        response.headers()["set-auth-jwt"]
            .to_str()
            .unwrap()
            .contains('.')
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS],
        "X-First, Set-Auth-Jwt, set-auth-jwt"
    );
    assert!(json_body(response).await["session"].is_object());

    fixture.service.sign_out(&credential.opaque).await.unwrap();
    let response = get(
        &fixture.app,
        "/api/auth/get-session",
        Some(&credential.cookie),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("set-auth-jwt"));
    assert_eq!(json_body(response).await, Value::Null);
}

#[tokio::test]
async fn disable_flag_affects_only_session_header_and_token_responses_are_no_store() {
    let config = JwtConfig {
        disable_setting_jwt_header: true,
        ..JwtConfig::default()
    };
    let fixture = fixture(config);
    let credential = signup(&fixture, "disabled-header").await;
    let response = get(
        &fixture.app,
        "/api/auth/get-session",
        Some(&credential.cookie),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("set-auth-jwt"));

    let response = get(&fixture.app, "/api/auth/token", Some(&credential.cookie)).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert!(json_body(response).await["token"].as_str().is_some());

    let response = get(&fixture.app, "/api/auth/token", None).await;
    assert_eq!(response.status(), 401);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
}

#[tokio::test]
async fn session_header_signing_failure_fails_closed_with_no_store_headers() {
    let mut config = JwtConfig::default();
    config.jwks.remote_url = Some("kms-jwks".into());
    config.jwks.key_pair_config = Some(JwkAlgorithm::EdDsa);
    config.jwt.sign = Some(Arc::new(FailingSigner));
    let fixture = fixture(config);
    let credential = signup(&fixture, "failing-header").await;
    let response = get(
        &fixture.app,
        "/api/auth/get-session",
        Some(&credential.cookie),
    )
    .await;
    assert!(!response.status().is_success());
    assert!(!response.headers().contains_key("set-auth-jwt"));
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
}
