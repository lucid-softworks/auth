use super::support::{
    fixture, fixture_with, generate, generated_token, json_body, session_cookie, signup,
    signup_response, verify,
};
use async_trait::async_trait;
use axum::{
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use chrono::{Duration, Utc};
use lucid_auth::{
    AuthError, AuthPlugin, AuthService, AuthStore, BeforeDatabaseCreateHook, DatabaseCreateRecord,
    DatabaseHookContext, DatabaseHooks, DatabaseModel, OneTimeTokenConfig, OneTimeTokenGenerator,
    OneTimeTokenRequestContext, PluginDescriptor, PluginRequestContext, SessionWithUser,
};
use serde_json::json;
use std::sync::Arc;

struct ExistingExposeHeader;

struct FailingGenerator;

#[async_trait]
impl OneTimeTokenGenerator for FailingGenerator {
    async fn generate(
        &self,
        _session: &SessionWithUser,
        _context: &OneTimeTokenRequestContext,
    ) -> Result<String, AuthError> {
        Err(AuthError::Storage("one-time-token generator failed".into()))
    }
}

struct RejectVerificationPersistence;

#[async_trait]
impl DatabaseHooks for RejectVerificationPersistence {
    async fn before_create(
        &self,
        record: &DatabaseCreateRecord,
        _context: &DatabaseHookContext,
    ) -> Result<BeforeDatabaseCreateHook, AuthError> {
        if record.model() == DatabaseModel::Verification {
            return Err(AuthError::Storage(
                "one-time-token persistence failed".into(),
            ));
        }
        Ok(BeforeDatabaseCreateHook::Continue)
    }
}

#[async_trait]
impl AuthPlugin for ExistingExposeHeader {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "one-time-token-header-fixture",
            display_name: "one-time-token header fixture",
            version: "1.7.2",
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
        if request.path == "/sign-up/email" {
            response.headers_mut().insert(
                header::ACCESS_CONTROL_EXPOSE_HEADERS,
                HeaderValue::from_static("X-First, Set-Ott, X-First"),
            );
        }
        response
    }

    fn contributes_on_response(&self) -> bool {
        true
    }
}

fn enabled_config() -> OneTimeTokenConfig {
    OneTimeTokenConfig {
        set_ott_header_on_new_session: true,
        ..OneTimeTokenConfig::default()
    }
}

fn ott(response: &Response) -> Option<String> {
    response
        .headers()
        .get("set-ott")
        .map(|value| value.to_str().unwrap().to_owned())
}

#[tokio::test]
async fn header_is_disabled_by_default_and_enabled_for_new_sessions() {
    let disabled = fixture(OneTimeTokenConfig::default());
    let response = signup_response(&disabled.app, "header-default").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(ott(&response).is_none());

    let enabled = fixture(enabled_config());
    let response = signup_response(&enabled.app, "header-enabled").await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = session_cookie(&response).unwrap();
    let token = ott(&response).expect("new session one-time token header");
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS],
        "set-ott"
    );
    let signup_body = json_body(response).await;

    let redeemed = verify(&enabled.app, &token, None).await;
    assert_eq!(redeemed.status(), StatusCode::OK);
    assert!(session_cookie(&redeemed).is_some());
    assert_ne!(ott(&redeemed).as_deref(), Some(token.as_str()));
    let successor = ott(&redeemed).expect("verification cookie mints a successor");
    assert_eq!(
        redeemed.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS],
        "set-ott"
    );
    let body = json_body(redeemed).await;
    assert_eq!(body["user"]["id"], signup_body["user"]["id"]);

    let successor_response = verify(&enabled.app, &successor, Some(&cookie)).await;
    assert_eq!(successor_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn expose_headers_merge_with_case_sensitive_set_deduplication() {
    let fixture = fixture_with(enabled_config(), |auth| {
        auth.add_plugin(ExistingExposeHeader).unwrap();
    });
    let response = signup_response(&fixture.app, "header-merge").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(ott(&response).is_some());
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS],
        "X-First, Set-Ott, set-ott"
    );
}

#[tokio::test]
async fn verify_without_cookie_binding_does_not_mint_a_successor() {
    let fixture = fixture(OneTimeTokenConfig {
        set_ott_header_on_new_session: true,
        disable_set_session_cookie: true,
        ..OneTimeTokenConfig::default()
    });
    let source = signup(&fixture, "no-successor").await;
    let token = generated_token(generate(&fixture.app, Some(&source.cookie)).await).await;
    let response = verify(&fixture.app, &token, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(session_cookie(&response).is_none());
    assert!(ott(&response).is_none());
}

#[tokio::test]
async fn expired_session_error_mints_the_pinned_successor_token() {
    let fixture = fixture(enabled_config());
    let source = signup(&fixture, "expired-successor").await;
    let token = generated_token(generate(&fixture.app, Some(&source.cookie)).await).await;
    fixture
        .store
        .expire_session(&source.session_id, Utc::now() - Duration::seconds(1))
        .await
        .unwrap();

    let response = verify(&fixture.app, &token, None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(session_cookie(&response).is_some());
    let successor = ott(&response).expect("expired session still mints pinned successor");
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS],
        "set-ott"
    );
    assert_eq!(
        json_body(response).await,
        json!({ "code": "BAD_REQUEST", "message": "Session expired" })
    );
    let retry = verify(&fixture.app, &successor, None).await;
    assert_eq!(retry.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(retry).await["message"], "Session expired");
}

#[tokio::test]
async fn header_generation_and_persistence_failures_fail_the_originating_request() {
    let generation = fixture(OneTimeTokenConfig {
        set_ott_header_on_new_session: true,
        generator: Some(Arc::new(FailingGenerator)),
        ..OneTimeTokenConfig::default()
    });
    let response = signup_response(&generation.app, "header-generation-failure").await;
    assert!(!response.status().is_success());
    assert!(ott(&response).is_none());

    let persistence = fixture_with(enabled_config(), |auth| {
        auth.database_hooks = Some(Arc::new(RejectVerificationPersistence));
    });
    let response = signup_response(&persistence.app, "header-persistence-failure").await;
    assert!(!response.status().is_success());
    assert!(ott(&response).is_none());
}
