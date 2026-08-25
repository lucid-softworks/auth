use super::support::{fixture, generate, verify_body};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use lucid_auth::{
    AuthConfig, AuthService, DatabaseModel, MemoryStore, OneTimeTokenConfig, OneTimeTokenStorage,
    PluginHttpMethod,
};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

#[test]
fn option_defaults_match_better_auth_1_7_1() {
    let config = OneTimeTokenConfig::default();
    assert_eq!(config.expires_in, chrono::Duration::minutes(3));
    assert!(!config.disable_client_request);
    assert!(config.generator.is_none());
    assert!(!config.disable_set_session_cookie);
    assert!(matches!(config.token_storage, OneTimeTokenStorage::Plain));
    assert!(!config.set_ott_header_on_new_session);
}

#[tokio::test]
async fn plugin_is_optional_and_declares_only_the_pinned_surface() {
    let baseline = Arc::new(AuthService::new(
        Arc::new(MemoryStore::default()),
        AuthConfig::new([172_u8; 32]).unwrap(),
    ));
    let baseline_app = lucid_auth::axum::router(baseline.clone());
    assert_eq!(
        generate(&baseline_app, None).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        verify_body(&baseline_app, json!({ "token": "missing" }), None)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    let fixture = fixture(OneTimeTokenConfig::default());
    let descriptor = fixture
        .service
        .plugin_metadata()
        .iter()
        .find(|plugin| plugin.id == "one-time-token")
        .unwrap();
    assert_eq!(descriptor.version, "1.7.1");
    assert!(descriptor.dependencies.is_empty());
    assert!(descriptor.conflicts.is_empty());
    assert!(descriptor.cookies.is_empty());
    assert!(descriptor.rate_limits.is_empty());
    assert!(descriptor.middleware.is_empty());
    assert_eq!(
        descriptor
            .endpoints
            .iter()
            .map(|endpoint| (
                endpoint.method,
                endpoint.path.as_ref(),
                endpoint.client_method
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                PluginHttpMethod::Get,
                "/one-time-token/generate",
                "oneTimeToken.generate"
            ),
            (
                PluginHttpMethod::Post,
                "/one-time-token/verify",
                "oneTimeToken.verify"
            )
        ]
    );
    let client = descriptor.client.unwrap();
    assert_eq!(client.package, "better-auth");
    assert_eq!(client.import_path, "better-auth/client/plugins");
    assert_eq!(client.factory, "oneTimeTokenClient");
    assert_eq!(client.better_auth_version, Some("1.7.1"));
    assert!(fixture.service.plugin_migrations().is_empty());

    for model in [
        DatabaseModel::User,
        DatabaseModel::Session,
        DatabaseModel::Account,
        DatabaseModel::Verification,
    ] {
        assert_eq!(
            fixture.service.database_schema_fields(model).len(),
            baseline.database_schema_fields(model).len()
        );
    }
}

#[tokio::test]
async fn endpoint_methods_are_exact() {
    let fixture = fixture(OneTimeTokenConfig::default());
    let generate_post = fixture
        .app
        .clone()
        .oneshot(
            Request::post("/api/auth/one-time-token/generate")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(generate_post.status(), StatusCode::METHOD_NOT_ALLOWED);

    let verify_get = fixture
        .app
        .oneshot(
            Request::get("/api/auth/one-time-token/verify")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verify_get.status(), StatusCode::METHOD_NOT_ALLOWED);
}
