use super::support::{response_text, send};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Duration;
use lucid_auth::{
    AuthConfig, AuthService, DatabaseModel, MemoryStore, OAuthProxyConfig, OAuthProxyPlugin,
    OAuthProxySecret, OAuthProxyVersionedSecret, PluginHttpMethod,
};
use std::{collections::BTreeMap, sync::Arc};

#[test]
fn option_defaults_and_secret_shapes_match_better_auth_1_7_1() {
    let defaults = OAuthProxyConfig::default();
    assert!(defaults.current_url.is_none());
    assert!(defaults.production_url.is_none());
    assert_eq!(defaults.max_age, Duration::seconds(60));
    assert!(defaults.secret.is_none());

    let plain = OAuthProxySecret::from("shared-proxy-secret");
    assert!(matches!(plain, OAuthProxySecret::Plain(_)));
    assert!(!format!("{plain:?}").contains("shared-proxy-secret"));

    let versioned = OAuthProxySecret::Versioned(OAuthProxyVersionedSecret {
        current_version: 2,
        keys: BTreeMap::from([
            (1, b"retired-proxy-secret".to_vec()),
            (2, b"current-proxy-secret".to_vec()),
        ]),
        legacy_secret: Some(b"legacy-proxy-secret".to_vec()),
    });
    let debug = format!("{versioned:?}");
    assert!(debug.contains("current_version: 2"));
    for material in [
        "retired-proxy-secret",
        "current-proxy-secret",
        "legacy-proxy-secret",
    ] {
        assert!(!debug.contains(material));
    }
}

#[tokio::test]
async fn plugin_is_optional_and_declares_only_the_pinned_server_surface() {
    let baseline = Arc::new(AuthService::new(
        Arc::new(MemoryStore::default()),
        AuthConfig::new([201_u8; 32]).unwrap(),
    ));
    let baseline_app = lucid_auth::axum::router(baseline.clone());
    let absent = send(
        &baseline_app,
        Request::get(
            "/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard&profile=not-encrypted",
        )
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(absent.status(), StatusCode::NOT_FOUND);

    let mut config = AuthConfig::new([202_u8; 32]).unwrap();
    config.add_plugin(OAuthProxyPlugin::default()).unwrap();
    let enabled = AuthService::new(Arc::new(MemoryStore::default()), config);
    let descriptor = enabled
        .plugin_metadata()
        .iter()
        .find(|plugin| plugin.id == "oauth-proxy")
        .unwrap();
    assert_eq!(descriptor.version, "1.7.2");
    assert_eq!(descriptor.display_name, "Better Auth OAuth Proxy");
    assert!(descriptor.dependencies.is_empty());
    assert!(descriptor.conflicts.is_empty());
    assert!(descriptor.cookies.is_empty());
    assert!(descriptor.rate_limits.is_empty());
    assert!(descriptor.middleware.is_empty());
    assert!(descriptor.client.is_none());
    assert_eq!(descriptor.endpoints.len(), 1);
    assert_eq!(descriptor.endpoints[0].method, PluginHttpMethod::Get);
    assert_eq!(descriptor.endpoints[0].path, "/oauth-proxy-callback");
    assert_eq!(descriptor.endpoints[0].client_method, "oAuthProxy");
    assert!(enabled.plugin_migrations().is_empty());

    for model in [
        DatabaseModel::User,
        DatabaseModel::Session,
        DatabaseModel::Account,
        DatabaseModel::Verification,
    ] {
        assert_eq!(
            enabled.database_schema_fields(model).len(),
            baseline.database_schema_fields(model).len()
        );
    }
}

#[tokio::test]
async fn callback_endpoint_accepts_get_only_and_requires_callback_url() {
    let mut config = AuthConfig::new([203_u8; 32]).unwrap();
    config.set_base_url("https://preview.example.test").unwrap();
    config.add_plugin(OAuthProxyPlugin::default()).unwrap();
    let app = lucid_auth::axum::router(Arc::new(AuthService::new(
        Arc::new(MemoryStore::default()),
        config,
    )));

    let missing = send(
        &app,
        Request::get("/api/auth/oauth-proxy-callback")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&response_text(missing).await).unwrap(),
        serde_json::json!({
            "code": "VALIDATION_ERROR",
            "message": "[query.callbackURL] Invalid input: expected string, received undefined"
        })
    );

    let post = send(
        &app,
        Request::post("/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
}
