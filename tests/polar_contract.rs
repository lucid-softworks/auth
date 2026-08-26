use lucid_auth::{
    AuthConfig, AuthPlugin, AuthService, BuiltinProvider, BuiltinProviderKind, CheckoutOptions,
    MemoryStore, PluginHttpMethod, PolarFeature, PolarHttpClient, PolarOptions, PolarPlugin,
    PortalOptions, UsageOptions, WebhooksOptions,
};
use std::sync::Arc;

fn plugin(features: Vec<PolarFeature>) -> PolarPlugin {
    PolarPlugin::new(PolarOptions::new(
        Arc::new(PolarHttpClient::new("polar_contract_token")),
        features,
    ))
}

#[test]
fn descriptor_and_official_client_metadata_match_polar_1_8_4() {
    let descriptor = plugin(vec![]).descriptor();

    assert_eq!(descriptor.id, "polar");
    assert_eq!(descriptor.display_name, "Polar");
    assert_eq!(descriptor.version, "1.8.4");
    assert!(descriptor.dependencies.is_empty());
    assert!(descriptor.conflicts.is_empty());
    assert!(descriptor.endpoints.is_empty());
    assert!(descriptor.cookies.is_empty());
    assert!(descriptor.rate_limits.is_empty());
    assert!(descriptor.middleware.is_empty());

    let client = descriptor
        .client
        .expect("Polar has official client metadata");
    assert_eq!(client.package, "@polar-sh/better-auth");
    assert_eq!(client.import_path, "@polar-sh/better-auth/client");
    assert_eq!(client.factory, "polarClient");
    assert_eq!(client.better_auth_version, Some("1.7.1"));
    assert_eq!(client.client_id, Some("polar-client"));
    assert_eq!(client.client_version, Some("1.8.4"));
    assert_eq!(client.custom_actions, ["checkoutEmbed"]);
    assert_eq!(client.non_action_paths, ["/polar/webhooks"]);
}

#[test]
fn configured_features_contribute_only_the_pinned_endpoint_inventory() {
    let endpoints = plugin(vec![
        PolarFeature::Checkout(CheckoutOptions::default()),
        PolarFeature::Portal(PortalOptions::default()),
        PolarFeature::Usage(UsageOptions::default()),
        PolarFeature::Webhooks(WebhooksOptions::new("polar_webhook_secret")),
    ])
    .descriptor()
    .endpoints;

    assert_eq!(
        endpoints
            .iter()
            .map(|endpoint| (
                endpoint.method,
                endpoint.path.as_ref(),
                endpoint.client_method,
            ))
            .collect::<Vec<_>>(),
        vec![
            (PluginHttpMethod::Post, "/checkout", "checkout"),
            (PluginHttpMethod::Get, "/customer/portal", "customer.portal",),
            (
                PluginHttpMethod::Post,
                "/customer/portal",
                "customer.portal",
            ),
            (PluginHttpMethod::Get, "/customer/state", "customer.state",),
            (
                PluginHttpMethod::Get,
                "/customer/benefits/list",
                "customer.benefits.list",
            ),
            (
                PluginHttpMethod::Get,
                "/customer/subscriptions/list",
                "customer.subscriptions.list",
            ),
            (
                PluginHttpMethod::Get,
                "/customer/orders/list",
                "customer.orders.list",
            ),
            (
                PluginHttpMethod::Get,
                "/usage/meters/list",
                "usage.meters.list",
            ),
            (PluginHttpMethod::Post, "/usage/ingest", "usage.ingest",),
            (PluginHttpMethod::Post, "/polar/webhooks", "polarWebhooks",),
        ]
    );
}

#[test]
fn plugin_contributes_lifecycle_hooks_but_no_schema_or_migrations() {
    assert!(plugin(vec![]).database_hooks().is_some());
    let mut options = PolarOptions::new(
        Arc::new(PolarHttpClient::new("polar_contract_token")),
        vec![],
    );
    options.create_customer_on_sign_up = true;
    let plugin = PolarPlugin::new(options);

    assert!(plugin.database_hooks().is_some());
    assert!(plugin.schema().is_empty());
    assert!(plugin.migrations().is_empty());

    let mut config = AuthConfig::new([73_u8; 32]).unwrap();
    config.add_plugin(plugin).unwrap();
    let service = AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap();
    assert!(service.plugin_migrations().is_empty());
}

#[test]
fn polar_adapter_and_builtin_polar_oauth_provider_can_be_installed_together() {
    let mut config = AuthConfig::new([74_u8; 32]).unwrap();
    config.set_base_url("https://auth.example.com").unwrap();
    config
        .add_social_provider(BuiltinProvider::new(
            BuiltinProviderKind::Polar,
            "polar_oauth_client",
            "polar_oauth_secret",
        ))
        .unwrap();
    config.add_plugin(plugin(vec![])).unwrap();

    let service = AuthService::try_new(Arc::new(MemoryStore::default()), config)
        .expect("the Polar adapter ID must not conflict with the Polar social-provider ID");
    assert_eq!(service.plugin_metadata()[0].id, "polar");
}
