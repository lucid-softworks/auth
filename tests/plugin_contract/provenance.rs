use super::{MetadataPlugin, descriptor};
use lucid_auth::{
    AuthConfig, AuthError, AuthPlugin, AuthService, BearerPlugin, MemoryStore,
    PluginArtifactMetadata, PluginClientMetadata, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod, PluginProvenance, UsernamePlugin,
};
use serde_json::{Value, json};
use std::{borrow::Cow, sync::Arc};

#[test]
fn serialized_descriptors_distinguish_client_server_and_extension_provenance() {
    let pinned = serde_json::to_value(UsernamePlugin::default().descriptor()).unwrap();
    assert_eq!(
        pinned["provenance"],
        json!({
            "classification": "pinnedBetterAuthPort",
            "betterAuthVersion": "1.7.2",
            "server": {
                "package": "better-auth",
                "version": "1.7.2",
                "importPath": "better-auth/plugins",
                "export": "username",
            },
        })
    );
    assert_eq!(
        pinned["client"]["provenance"],
        Value::String("officialUpstream".into())
    );

    let server_only = serde_json::to_value(BearerPlugin::default().descriptor()).unwrap();
    assert_eq!(server_only["client"], Value::Null);
    assert_eq!(
        server_only["provenance"]["server"]["export"],
        Value::String("bearer".into())
    );

    let extension = serde_json::to_value(descriptor("extension", &[], &[], &[])).unwrap();
    assert_eq!(
        extension["provenance"],
        json!({ "classification": "lucidExtension" })
    );
    assert_eq!(extension["client"], Value::Null);
}

#[test]
fn startup_rejects_incomplete_or_contradictory_provenance_claims() {
    let invalid = |descriptor: PluginDescriptor| {
        let mut config = AuthConfig::new([110_u8; 32]).unwrap();
        config.add_plugin(MetadataPlugin(descriptor)).unwrap();
        AuthService::try_new(Arc::new(MemoryStore::default()), config)
            .err()
            .expect("invalid provenance")
    };

    let mut incomplete = descriptor("incomplete", &[], &[], &[]);
    incomplete.provenance = PluginProvenance::better_auth(PluginArtifactMetadata::new(
        "better-auth",
        "1.0.0",
        "better-auth/plugins",
        "",
    ));
    assert!(matches!(
        invalid(incomplete),
        AuthError::InvalidConfiguration(_)
    ));

    let mut version_mismatch = descriptor("version-mismatch", &[], &[], &[]);
    version_mismatch.provenance = PluginProvenance::better_auth(PluginArtifactMetadata::new(
        "better-auth",
        "1.7.2",
        "better-auth/plugins",
        "fixture",
    ));
    assert!(matches!(
        invalid(version_mismatch),
        AuthError::InvalidConfiguration(_)
    ));

    let mut false_official_client = descriptor("false-client", &[], &[], &[]);
    false_official_client.client = Some(PluginClientMetadata::official(
        "better-auth",
        "better-auth/client/plugins",
        "fixtureClient",
    ));
    assert!(matches!(
        invalid(false_official_client),
        AuthError::InvalidConfiguration(_)
    ));

    let mut application_evidence = descriptor("application-evidence", &[], &[], &[]);
    application_evidence.provenance =
        PluginProvenance::pinned_upstream("better-auth", "1.0.0", "better-auth/plugins", "fixture");
    application_evidence.client = Some(PluginClientMetadata::application(
        "@example/fixture",
        "@example/fixture/client",
        "fixtureClient",
    ));
    assert!(matches!(
        invalid(application_evidence),
        AuthError::InvalidConfiguration(_)
    ));
}

#[test]
fn pinned_ports_and_extensions_share_registry_collision_checks() {
    const COLLISION: &[PluginEndpoint] = &[PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: Cow::Borrowed("/provenance-collision"),
        client_method: "fixture.collision",
    }];
    let extension = descriptor("extension-collision", &[], &[], COLLISION);
    let mut pinned = descriptor("pinned-collision", &[], &[], COLLISION);
    pinned.provenance =
        PluginProvenance::pinned_upstream("better-auth", "1.0.0", "better-auth/plugins", "fixture");
    let mut config = AuthConfig::new([111_u8; 32]).unwrap();
    config.add_plugin(MetadataPlugin(extension)).unwrap();
    config.add_plugin(MetadataPlugin(pinned)).unwrap();
    assert!(matches!(
        AuthService::try_new(Arc::new(MemoryStore::default()), config),
        Err(AuthError::InvalidConfiguration(_))
    ));
}
