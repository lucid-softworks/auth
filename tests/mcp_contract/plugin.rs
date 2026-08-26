use super::support::*;
use lucid_auth::OAuthProviderPlugin;

#[test]
fn preset_is_the_oauth_provider_and_uses_only_the_inherited_surface() {
    let plugin = plugin();
    let descriptor = plugin.descriptor();
    assert_eq!(descriptor.id, "oauth-provider");
    assert_eq!(descriptor.client.unwrap().factory, "oauthProviderClient");
    assert_eq!(plugin.rate_limits().len(), 6);
    assert!(plugin.migrations().is_empty());
    assert_eq!(
        plugin.oauth_provider_config().refresh_token_reuse_interval,
        30
    );
    assert_eq!(
        plugin.oauth_provider_config().resources[0].identifier,
        RESOURCE
    );
    assert_eq!(
        plugin
            .oauth_provider_config()
            .client_registration_default_resources,
        [RESOURCE]
    );

    let mut provider = OAuthProviderPluginConfig::new("/login", "/consent");
    provider.schema.oauth_client.model_name = Some("mcpClients".into());
    provider
        .schema
        .oauth_client
        .fields
        .insert("clientId".into(), "clientKey".into());
    let custom = McpPlugin::in_memory(McpPluginConfig::new(RESOURCE, provider)).unwrap();
    let mut config = AuthConfig::new([215_u8; 32]).unwrap();
    config.add_plugin(JwtPlugin::default()).unwrap();
    config.add_plugin(custom).unwrap();
    let service = AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap();
    assert!(service.plugin_migrations().is_empty());
    let logical_client = service.database_schema().table("oauthClient").unwrap();
    assert_eq!(logical_client.model_name, "mcpClients");
    assert_eq!(
        logical_client.fields["clientId"].field_name.as_deref(),
        Some("clientKey")
    );
    let generic = service.generic_database_schema();
    let physical_client = generic.table("mcpClients").unwrap();
    assert!(physical_client.fields.contains_key("clientKey"));
    assert!(!physical_client.fields.contains_key("clientId"));
    assert!(generic.table("oauthClient").is_none());
}

#[test]
fn preset_cannot_be_combined_with_a_second_oauth_provider() {
    let mut config = AuthConfig::new([214_u8; 32]).unwrap();
    config.add_plugin(plugin()).unwrap();
    let error = config
        .add_plugin(OAuthProviderPlugin::in_memory(
            OAuthProviderPluginConfig::new("/login", "/consent"),
        ))
        .unwrap_err();
    assert!(error.to_string().contains("oauth-provider"));
}
