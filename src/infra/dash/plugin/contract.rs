use super::*;
use std::time::Duration;

#[test]
fn descriptor_owns_the_exact_core_family() {
    let descriptor = DashPlugin::default().descriptor();
    assert_eq!(descriptor.id, "dash");
    assert_eq!(descriptor.version, "0.4.3");
    assert_eq!(descriptor.endpoints.len(), 30);
    assert_eq!(
        descriptor
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.method == PluginHttpMethod::Get)
            .count(),
        14
    );
    assert_eq!(
        descriptor
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.method == PluginHttpMethod::Post)
            .count(),
        16
    );
}

#[test]
fn client_exposes_only_the_two_nested_audit_actions() {
    let client = DashPlugin::default().descriptor().client.unwrap();
    assert_eq!(client.client_id, Some("dash"));
    assert_eq!(client.custom_actions, CLIENT_ACTIONS);
    assert_eq!(client.non_action_paths, CLIENT_NON_ACTION_PATHS);
    assert_eq!(client.path_methods, CLIENT_PATH_METHODS);
}

#[test]
fn activity_schema_is_strictly_opt_in() {
    assert!(DashPlugin::default().schema().is_empty());
    let plugin = DashPlugin::new(DashOptions {
        activity_tracking: DashActivityTracking {
            enabled: true,
            ..DashActivityTracking::default()
        },
        ..DashOptions::default()
    });
    let schema = plugin.schema();
    assert_eq!(schema.len(), 1);
    assert_eq!(schema[0].logical_name, "user");
    assert_eq!(schema[0].model_name, None);
    assert!(schema[0].fields.contains_key("lastActiveAt"));
}

#[test]
fn activity_interval_defaults_to_five_minutes() {
    assert_eq!(
        DashActivityTracking::default().update_interval,
        Duration::from_millis(300_000)
    );
}

#[cfg(feature = "axum")]
#[test]
fn activity_interval_uses_the_pinned_strict_boundary() {
    let now = chrono::Utc::now();
    let interval = Duration::from_secs(300);
    assert!(activity_was_recent(
        Some(&serde_json::json!(now - chrono::Duration::seconds(299))),
        interval,
        now,
    ));
    assert!(!activity_was_recent(
        Some(&serde_json::json!(now - chrono::Duration::seconds(300))),
        interval,
        now,
    ));
    assert!(!activity_was_recent(None, interval, now));
}
