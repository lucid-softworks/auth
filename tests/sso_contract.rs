use lucid_auth::{
    AdditionalFieldType, AuthPlugin, PluginHttpMethod, PluginProvenance, SSO_VERSION, SsoOptions,
    SsoPlugin,
};

#[test]
fn descriptor_matches_the_pinned_server_and_official_client() {
    let descriptor = SsoPlugin::default().descriptor();
    assert_eq!(descriptor.id, "sso");
    assert_eq!(descriptor.version, "1.7.1");
    assert_eq!(SSO_VERSION, "1.7.1");
    assert!(matches!(
        descriptor.provenance,
        PluginProvenance::PinnedBetterAuthPort { .. }
    ));
    assert_eq!(descriptor.endpoints.len(), 14);
    assert_eq!(
        descriptor
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.path == "/sso/saml2/sp/acs/:providerId")
            .map(|endpoint| endpoint.method)
            .collect::<Vec<_>>(),
        vec![PluginHttpMethod::Get, PluginHttpMethod::Post]
    );
    let client = descriptor.client.expect("official client metadata");
    assert_eq!(client.package, "@better-auth/sso");
    assert_eq!(client.import_path, "@better-auth/sso/client");
    assert_eq!(client.factory, "ssoClient");
    assert_eq!(client.client_id, Some("sso-client"));
    assert_eq!(client.path_methods.len(), 2);
}

#[test]
fn schema_and_domain_verification_are_conditional() {
    let plugin = SsoPlugin::default();
    let schema = plugin.schema();
    assert_eq!(schema.len(), 1);
    let provider = &schema[0];
    assert_eq!(provider.logical_name, "ssoProvider");
    assert_eq!(provider.model_name.as_deref(), Some("ssoProvider"));
    assert_eq!(provider.fields.len(), 7);
    assert!(!provider.fields.contains_key("domainVerified"));
    assert_eq!(
        provider.fields["oidcConfig"].field_type,
        AdditionalFieldType::String
    );
    assert!(!provider.fields["oidcConfig"].required);
    assert!(provider.fields["providerId"].unique);

    let enabled = SsoPlugin::new(SsoOptions {
        domain_verification: true,
    });
    let enabled_schema = enabled.schema();
    let verified = &enabled_schema[0].fields["domainVerified"];
    assert_eq!(verified.field_type, AdditionalFieldType::Boolean);
    assert!(!verified.required);
    assert_eq!(enabled.descriptor().endpoints.len(), 16);
}
