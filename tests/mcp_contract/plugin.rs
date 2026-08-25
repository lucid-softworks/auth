use super::support::*;
use lucid_auth::OAuthProviderPlugin;

#[test]
fn preset_is_the_oauth_provider_and_uses_only_the_inherited_surface() {
    let plugin = plugin();
    let descriptor = plugin.descriptor();
    assert_eq!(descriptor.id, "oauth-provider");
    assert_eq!(descriptor.client.unwrap().factory, "oauthProviderClient");
    assert_eq!(plugin.rate_limits().len(), 6);
    assert_eq!(plugin.migrations().len(), 1);
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
