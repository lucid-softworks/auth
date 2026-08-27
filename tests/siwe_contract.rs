use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AdditionalFieldType, AuthConfig, AuthError, AuthService, AuthStore, MemoryStore,
    SessionStorageMode, SiweConfig, SiweMessageVerifier, SiweNonceGenerator, SiwePlugin,
    SiweVerificationRequest,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

#[path = "siwe_contract/validation_helpers.rs"]
mod validation_helpers;
use validation_helpers::*;
#[path = "siwe_contract/create_hooks.rs"]
mod create_hooks;
#[path = "siwe_contract/database_ids.rs"]
mod database_ids;
#[path = "siwe_contract/runtime_helpers.rs"]
mod runtime_helpers;

const ADDRESS: &str = "0x52908400098527886E0F7030069857D2E4169EE7";

struct Nonce(&'static str);

#[async_trait]
impl SiweNonceGenerator for Nonce {
    async fn generate(&self) -> Result<String, AuthError> {
        Ok(self.0.into())
    }
}

struct Verifier;

#[async_trait]
impl SiweMessageVerifier for Verifier {
    async fn verify(&self, _: SiweVerificationRequest) -> Result<bool, AuthError> {
        Ok(true)
    }
}

struct RejectingVerifier {
    fail: bool,
}

#[async_trait]
impl SiweMessageVerifier for RejectingVerifier {
    async fn verify(&self, _: SiweVerificationRequest) -> Result<bool, AuthError> {
        if self.fail {
            Err(AuthError::Storage("verifier exploded".into()))
        } else {
            Ok(false)
        }
    }
}

fn application(nonce: &'static str) -> (Router, Arc<AuthService>) {
    application_with_anonymous(nonce, true)
}

fn application_with_anonymous(nonce: &'static str, anonymous: bool) -> (Router, Arc<AuthService>) {
    application_with_verifier(nonce, anonymous, Arc::new(Verifier))
}

fn application_with_verifier(
    nonce: &'static str,
    anonymous: bool,
    verifier: Arc<dyn SiweMessageVerifier>,
) -> (Router, Arc<AuthService>) {
    let store = Arc::new(MemoryStore::default());
    let mut siwe = SiweConfig::new("example.com", Arc::new(Nonce(nonce)), verifier);
    siwe.anonymous = anonymous;
    let mut config = AuthConfig::new([122_u8; 32]).unwrap();
    config.set_base_url("https://example.com").unwrap();
    config
        .add_plugin(SiwePlugin::new(store.clone(), siwe))
        .unwrap();
    let service = Arc::new(AuthService::new(store, config));
    (lucid_auth::axum::router(service.clone()), service)
}

fn message(nonce: &str, domain: &str) -> String {
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n{ADDRESS}\n\n\
         URI: https://example.com\nVersion: 1\nChain ID: 1\nNonce: {nonce}\n\
         Issued At: 2026-08-24T12:00:00Z"
    )
}

async fn json_response(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn assert_default_wallet_schema(service: &AuthService) {
    let wallet = service.database_schema().table("walletAddress").unwrap();
    assert_eq!(wallet.model_name, "walletAddress");
    assert!(wallet.fields.contains_key("address"));
    let user_id = &wallet.fields["userId"];
    assert_eq!(user_id.field_type, AdditionalFieldType::String);
    let reference = user_id.references.as_ref().unwrap();
    assert_eq!(reference.model, "user");
    assert_eq!(reference.field, "id");
    assert!(
        service
            .generic_database_schema()
            .table("walletAddress")
            .unwrap()
            .fields
            .contains_key("address")
    );
}

#[tokio::test]
async fn descriptor_schema_and_both_nonce_routes_match_better_auth() {
    let (app, service) = application("route001");
    let descriptor = service
        .plugin_metadata()
        .iter()
        .find(|plugin| plugin.id == "siwe")
        .unwrap();
    assert_eq!(descriptor.client.unwrap().factory, "siweClient");
    assert_eq!(descriptor.endpoints.len(), 3);
    assert!(service.plugin_migrations().is_empty());
    assert_default_wallet_schema(&service);

    let store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([123_u8; 32]).unwrap();
    let mut custom = SiweConfig::new(
        "example.com",
        Arc::new(Nonce("schema01")),
        Arc::new(Verifier),
    );
    custom.schema.model_name = Some("custom\"wallets".into());
    custom.schema.address_field_name = Some("wallet\"address".into());
    config
        .add_plugin(SiwePlugin::new(store.clone(), custom))
        .unwrap();
    let custom = AuthService::new(store, config);
    assert!(custom.plugin_migrations().is_empty());
    let logical_wallet = custom.database_schema().table("walletAddress").unwrap();
    assert_eq!(logical_wallet.model_name, "custom\"wallets");
    assert_eq!(
        logical_wallet.fields["address"].field_name.as_deref(),
        Some("wallet\"address")
    );
    let generic = custom.generic_database_schema();
    let physical_wallet = generic.table("custom\"wallets").unwrap();
    assert!(physical_wallet.fields.contains_key("wallet\"address"));
    assert!(!physical_wallet.fields.contains_key("address"));
    assert!(generic.table("walletAddress").is_none());

    let response = app
        .oneshot(
            Request::post("/api/auth/siwe/nonce")
                .header(header::ORIGIN, "https://example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        json_response(response).await,
        (StatusCode::OK, json!({"nonce":"route001"}))
    );

    let (alias, _) = application("route002");
    let response = alias
        .oneshot(
            Request::post("/api/auth/siwe/get-nonce")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "https://example.com")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        json_response(response).await,
        (StatusCode::OK, json!({"nonce":"route002"}))
    );
}

#[tokio::test]
async fn official_verify_shape_returns_session_cookie_and_narrow_user() {
    let (app, _) = application("verify01");
    app.clone()
        .oneshot(
            Request::post("/api/auth/siwe/nonce")
                .header(header::ORIGIN, "https://example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let response = app
        .oneshot(
            Request::post("/api/auth/siwe/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "https://example.com")
                .body(Body::from(
                    json!({
                        "message": message("verify01", "example.com"),
                        "signature": "0xsigned"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|value| value
                .to_str()
                .unwrap()
                .contains("better-auth.session_token="))
    );
    let (_, body) = json_response(response).await;
    assert_eq!(body["success"], true);
    assert_eq!(body["user"]["walletAddress"], ADDRESS);
    assert_eq!(body["user"]["chainId"], 1.0);
    assert_eq!(body["user"].as_object().unwrap().len(), 3);
}

#[tokio::test]
async fn strict_bodies_nonce_bounds_and_replay_errors_are_exact() {
    let (invalid, _) = application("short");
    let response = invalid
        .oneshot(
            Request::post("/api/auth/siwe/nonce")
                .header(header::ORIGIN, "https://example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        json_response(response).await,
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({
                "code":"SIWE_INVALID_NONCE",
                "message":"SIWE getNonce must return an ERC-4361 nonce: 8-250 alphanumeric characters.",
                "status":500
            })
        )
    );

    let (app, _) = application("strict01");
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/auth/siwe/nonce")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{\"extra\":true}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = json_response(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({
            "code":"VALIDATION_ERROR",
            "message":"[body] Unrecognized key: \"extra\""
        })
    );

    app.clone()
        .oneshot(
            Request::post("/api/auth/siwe/nonce")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let verify = |domain| {
        Request::post("/api/auth/siwe/verify")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "message":message("strict01", domain),
                    "signature":"signed"
                })
                .to_string(),
            ))
            .unwrap()
    };
    let (status, body) =
        json_response(app.clone().oneshot(verify("evil.test")).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH");
    let (status, body) = json_response(app.oneshot(verify("example.com")).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");
}

#[tokio::test]
async fn validation_and_media_errors_match_better_auth_zod_contract() {
    let (app, _) = application("errors01");
    assert_empty_verify_body(app.clone()).await;
    assert_verify_validation_cases(app.clone()).await;
    assert_unsupported_media_type(app).await;
    assert_required_email_refinement().await;
}

#[tokio::test]
async fn signature_and_callback_failures_have_the_exact_upstream_api_error_shape() {
    for (nonce, fail, expected) in [
        (
            "reject01",
            false,
            json!({"message":"Unauthorized: Invalid SIWE signature","status":401}),
        ),
        (
            "failure1",
            true,
            json!({
                "message":"Something went wrong. Please try again later.",
                "error":"authentication storage failed: verifier exploded",
                "status":401
            }),
        ),
    ] {
        let (app, _) = application_with_verifier(nonce, true, Arc::new(RejectingVerifier { fail }));
        app.clone()
            .oneshot(
                Request::post("/api/auth/siwe/nonce")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let response = app
            .oneshot(
                Request::post("/api/auth/siwe/verify")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "message":message(nonce, "example.com"),
                            "signature":"signed"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            json_response(response).await,
            (StatusCode::UNAUTHORIZED, expected)
        );
    }
}
