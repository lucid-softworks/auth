use super::support::FakeChargebeeClient;
use lucid_auth::{
    AuthPlugin, CHARGEBEE_WEBHOOK_EVENT_TYPES, ChargebeeOptions, ChargebeePlugin,
    MemoryChargebeeStore, MemoryStore, PluginHttpMethod, PluginRequestSecurity,
};
use std::sync::Arc;

fn plugin() -> ChargebeePlugin {
    let auth_store = Arc::new(MemoryStore::default());
    ChargebeePlugin::new(
        ChargebeeOptions::new(Arc::new(FakeChargebeeClient::default())),
        Arc::new(MemoryChargebeeStore::new(auth_store)),
    )
}

#[test]
fn webhook_lifecycle_mapping_vocabulary_is_exact() {
    assert_eq!(
        CHARGEBEE_WEBHOOK_EVENT_TYPES,
        [
            "subscription_created",
            "subscription_activated",
            "subscription_started",
            "subscription_changed",
            "subscription_renewed",
            "subscription_scheduled_cancellation_removed",
            "subscription_cancelled",
            "customer_deleted",
        ]
    );
}

#[test]
fn descriptor_always_exposes_the_exact_eight_server_routes() {
    let descriptor = plugin().descriptor();
    assert_eq!(descriptor.id, "chargebee");
    assert_eq!(descriptor.display_name, "Chargebee Better Auth");
    assert_eq!(descriptor.version, "1.7.1");
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
                "/chargebee/webhook",
                "chargebeeWebhook"
            ),
            (
                PluginHttpMethod::Post,
                "/subscription/create",
                "subscription.create"
            ),
            (
                PluginHttpMethod::Post,
                "/subscription/update",
                "subscription.update"
            ),
            (
                PluginHttpMethod::Get,
                "/subscription/success",
                "subscriptionSuccess"
            ),
            (
                PluginHttpMethod::Post,
                "/subscription/cancel",
                "subscription.cancel"
            ),
            (
                PluginHttpMethod::Get,
                "/subscription/cancel/callback",
                "subscription.cancel.callback",
            ),
            (
                PluginHttpMethod::Post,
                "/subscription/portal",
                "subscription.portal"
            ),
            (
                PluginHttpMethod::Get,
                "/subscription/list",
                "subscription.list"
            ),
        ]
    );
}

#[test]
fn official_client_metadata_has_only_its_five_explicit_path_methods() {
    let client = plugin().descriptor().client.unwrap();
    assert_eq!(client.package, "@chargebee/better-auth");
    assert_eq!(client.import_path, "@chargebee/better-auth/client");
    assert_eq!(client.factory, "chargebeeClient");
    assert_eq!(client.client_id, Some("chargebee-client"));
    assert_eq!(client.client_version, Some("1.2.0"));
    assert_eq!(
        client
            .path_methods
            .iter()
            .map(|entry| (entry.path, entry.method))
            .collect::<Vec<_>>(),
        [
            ("/subscription/create", PluginHttpMethod::Post),
            ("/subscription/update", PluginHttpMethod::Post),
            ("/subscription/cancel", PluginHttpMethod::Post),
            ("/subscription/portal", PluginHttpMethod::Post),
            ("/subscription/list", PluginHttpMethod::Get),
        ]
    );
    assert_eq!(
        client.non_action_paths,
        ["/chargebee/webhook", "/subscription/success"]
    );
}

#[test]
fn webhook_and_callbacks_keep_their_exact_security_metadata() {
    let plugin = plugin();
    assert_eq!(
        plugin.request_security(PluginHttpMethod::Post, "/chargebee/webhook"),
        PluginRequestSecurity::RawPublic
    );
    assert_eq!(
        plugin.request_origin_fields(PluginHttpMethod::Get, "/subscription/success"),
        ["callbackURL"]
    );
    assert_eq!(
        plugin.request_origin_fields(PluginHttpMethod::Get, "/subscription/cancel/callback"),
        ["callbackURL"]
    );
}
