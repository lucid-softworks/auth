use lucid_auth::{
    AdditionalFieldType, AuthConfig, AuthPlugin, CreemModelSchema, CreemOptions, CreemPlugin,
    MemoryStore, PluginHttpMethod, PluginRequestSecurity,
};
use std::sync::Arc;

fn plugin(options: CreemOptions) -> CreemPlugin {
    CreemPlugin::in_memory(options, Arc::new(MemoryStore::default()))
}

#[test]
fn descriptor_matches_the_exact_six_method_server_surface() {
    let disabled = plugin(CreemOptions::new("key"));
    let descriptor = disabled.descriptor();

    assert_eq!(descriptor.id, "creem");
    assert_eq!(descriptor.display_name, "Creem");
    assert_eq!(descriptor.version, "1.1.4");
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
        [
            (
                PluginHttpMethod::Post,
                "/creem/create-checkout",
                "createCheckout"
            ),
            (
                PluginHttpMethod::Post,
                "/creem/create-portal",
                "createPortal"
            ),
            (
                PluginHttpMethod::Post,
                "/creem/cancel-subscription",
                "cancelSubscription"
            ),
            (
                PluginHttpMethod::Post,
                "/creem/retrieve-subscription",
                "retrieveSubscription"
            ),
            (
                PluginHttpMethod::Post,
                "/creem/search-transactions",
                "searchTransactions"
            ),
            (
                PluginHttpMethod::Get,
                "/creem/has-access-granted",
                "hasAccessGranted"
            ),
        ]
    );
}

#[test]
fn descriptor_matches_the_client_and_conditional_webhook_surface() {
    let disabled = plugin(CreemOptions::new("key"));
    let descriptor = disabled.descriptor();
    let client = descriptor.client.unwrap();
    assert_eq!(client.package, "@creem_io/better-auth");
    assert_eq!(client.import_path, "@creem_io/better-auth/client");
    assert_eq!(client.factory, "creemClient");
    assert_eq!(client.client_id, Some("creem"));
    assert_eq!(client.client_version, Some("1.1.4"));
    assert_eq!(client.non_action_paths, ["/creem/webhook"]);

    let mut options = CreemOptions::new("key");
    options.webhook_secret = Some("whsec_contract".into());
    let enabled = plugin(options);
    let descriptor = enabled.descriptor();
    assert_eq!(descriptor.endpoints.len(), 7);
    assert_eq!(
        descriptor.endpoints.last().map(|endpoint| (
            endpoint.method,
            endpoint.path.as_ref(),
            endpoint.client_method,
        )),
        Some((PluginHttpMethod::Post, "/creem/webhook", "creemWebhook"))
    );
    assert_eq!(
        enabled.request_security(PluginHttpMethod::Post, "/creem/webhook"),
        PluginRequestSecurity::RawPublic
    );
}

#[test]
fn persistence_exactly_controls_schema_and_remapping_validation() {
    let enabled = plugin(CreemOptions::new("key"));
    let fields = enabled.schema_fields();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].name, "creemCustomerId");
    assert_eq!(fields[0].field.field_type, AdditionalFieldType::String);
    assert!(!fields[0].field.required);
    assert!(fields[0].field.input);
    assert!(fields[0].field.returned);
    assert_eq!(fields[1].name, "hadTrial");
    assert_eq!(fields[1].field.field_type, AdditionalFieldType::Boolean);
    assert!(!fields[1].field.required);
    assert!(fields[1].field.input);
    assert!(fields[1].field.returned);
    assert_eq!(enabled.migrations().len(), 1);

    let mut options = CreemOptions::new("key");
    options.persist_subscriptions = false;
    let disabled = plugin(options.clone());
    assert!(disabled.schema_fields().is_empty());
    assert!(disabled.migrations().is_empty());

    options
        .schema
        .insert_model("user", CreemModelSchema::default());
    assert!(
        plugin(options)
            .validate(&AuthConfig::new([49; 32]).unwrap())
            .is_err()
    );
}
