use lucid_auth::{
    AuthConfig, MemoryOrganizationStore, OrganizationDynamicAccessControlConfig,
    OrganizationPlugin, OrganizationPluginConfig, OrganizationTeamsConfig,
};
use std::sync::Arc;

pub(super) fn register(config: &mut AuthConfig) {
    config
        .add_plugin(OrganizationPlugin::with_config(
            Arc::new(MemoryOrganizationStore::default()),
            OrganizationPluginConfig {
                teams: OrganizationTeamsConfig {
                    enabled: true,
                    ..OrganizationTeamsConfig::default()
                },
                dynamic_access_control: OrganizationDynamicAccessControlConfig {
                    enabled: true,
                    ..OrganizationDynamicAccessControlConfig::default()
                },
                ..OrganizationPluginConfig::default()
            },
        ))
        .expect("unique organization plugin");
}
