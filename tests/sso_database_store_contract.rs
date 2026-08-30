#![cfg(all(feature = "axum", feature = "sqlite"))]

use lucid_auth::{
    AuthConfig, AuthService, DatabaseSsoStore, EmailSignUpInput, NewSsoProvider, SsoOptions,
    SsoPlugin, SsoProviderUpdate, SsoStore,
    sqlite::{SqliteAdapterConfig, SqliteStore},
};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;

#[tokio::test]
async fn provider_catalog_round_trips_through_native_sqlite_transactions() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let auth_store = Arc::new(SqliteStore::new(pool, SqliteAdapterConfig::default()));
    let sso_store = Arc::new(DatabaseSsoStore::new(auth_store.clone()));
    let plugin = SsoPlugin::with_store(SsoOptions::default(), sso_store.clone());
    let mut config = AuthConfig::new([137_u8; 32]).unwrap();
    config.set_base_url("https://example.com").unwrap();
    config.email_and_password.enabled = true;
    config.add_plugin(plugin).unwrap();
    let service = AuthService::new(auth_store.clone(), config);
    auth_store
        .migrate(Arc::new(service.database_schema().clone()))
        .await
        .unwrap();
    let owner = service
        .sign_up_email(
            EmailSignUpInput {
                name: "SSO Owner".into(),
                email: "owner@example.com".into(),
                password: "correct horse battery staple".into(),
                image: None,
                callback_url: None,
                remember_me: None,
                username: None,
                display_username: None,
                additional_fields: serde_json::Map::new(),
            },
            None,
            None,
        )
        .await
        .unwrap()
        .user;

    let created = sso_store
        .create(NewSsoProvider {
            id: "sso-row".into(),
            issuer: "https://sp.example".into(),
            oidc_config: Some(serde_json::json!({
                "issuer": "https://idp.example",
                "clientId": "client",
                "clientSecret": "plaintext-upstream"
            })),
            saml_config: None,
            user_id: owner.id,
            provider_id: "workforce".into(),
            organization_id: Some("organization".into()),
            domain: "example.com".into(),
            domain_verified: None,
        })
        .await
        .unwrap();
    assert_eq!(created.provider_id, "workforce");
    assert_eq!(
        sso_store.find_by_provider_id("workforce").await.unwrap(),
        Some(created.clone())
    );

    let updated = sso_store
        .update(
            "sso-row",
            SsoProviderUpdate {
                domain: Some("login.example.com".into()),
                ..SsoProviderUpdate::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.domain, "login.example.com");
    assert_eq!(sso_store.list().await.unwrap(), vec![updated.clone()]);
    assert_eq!(sso_store.delete("sso-row").await.unwrap(), Some(updated));
    assert!(sso_store.list().await.unwrap().is_empty());
}
