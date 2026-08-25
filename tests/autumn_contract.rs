use lucid_auth::{
    AuthConfig, AuthPlugin, AuthService, AutumnOptions, AutumnPlugin, MemoryStore, PluginHttpMethod,
};
use std::sync::Arc;

#[test]
fn descriptor_matches_the_published_autumn_adapter_without_client_metadata() {
    let descriptor = AutumnPlugin::default().descriptor();

    assert_eq!(descriptor.id, "autumn");
    assert_eq!(descriptor.display_name, "Autumn");
    assert_eq!(descriptor.version, "1.2.53");
    assert!(descriptor.dependencies.is_empty());
    assert!(descriptor.conflicts.is_empty());
    assert!(descriptor.cookies.is_empty());
    assert!(descriptor.rate_limits.is_empty());
    assert!(descriptor.middleware.is_empty());
    assert!(descriptor.client.is_none());
    assert_eq!(descriptor.endpoints.len(), 15);
    assert!(
        descriptor
            .endpoints
            .iter()
            .all(|endpoint| endpoint.method == PluginHttpMethod::Post)
    );
    assert_eq!(
        descriptor
            .endpoints
            .iter()
            .map(|endpoint| endpoint.path.as_ref())
            .collect::<Vec<_>>(),
        [
            "/autumn/getOrCreateCustomer",
            "/autumn/getEntity",
            "/autumn/attach",
            "/autumn/previewAttach",
            "/autumn/updateSubscription",
            "/autumn/previewUpdateSubscription",
            "/autumn/openCustomerPortal",
            "/autumn/createReferralCode",
            "/autumn/redeemReferralCode",
            "/autumn/listPlans",
            "/autumn/listEvents",
            "/autumn/aggregateEvents",
            "/autumn/multiAttach",
            "/autumn/previewMultiAttach",
            "/autumn/setupPayment",
        ]
    );
}

#[test]
fn plugin_owns_no_database_or_lifecycle_surface() {
    let plugin = AutumnPlugin::default();
    assert!(plugin.schema_fields().is_empty());
    assert!(plugin.migrations().is_empty());
    assert!(plugin.database_hooks().is_none());

    let mut config = AuthConfig::new([81_u8; 32]).unwrap();
    config.add_plugin(plugin).unwrap();
    let service = AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap();
    assert!(service.plugin_migrations().is_empty());
}

#[test]
fn debug_output_redacts_the_explicit_secret() {
    let options = AutumnOptions {
        secret_key: Some("autumn_contract_secret".into()),
        ..AutumnOptions::default()
    };
    let debug = format!("{options:?}");
    assert!(!debug.contains("autumn_contract_secret"));
    assert!(debug.contains("[REDACTED]"));
}
