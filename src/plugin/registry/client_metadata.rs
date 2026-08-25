use crate::{
    PluginClientMetadata, PluginClientProvenance,
    protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
};

pub(super) fn validate(client: PluginClientMetadata, plugin_id: &str) -> Result<(), String> {
    if [client.package, client.import_path, client.factory]
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err(format!(
            "plugin '{plugin_id}' client metadata is incomplete"
        ));
    }
    if client.client_id.is_some() != client.client_version.is_some()
        || client
            .client_id
            .into_iter()
            .chain(client.client_version)
            .any(|value| value.trim().is_empty())
    {
        return Err(format!(
            "plugin '{plugin_id}' client identity metadata is incomplete"
        ));
    }
    match client.provenance {
        PluginClientProvenance::OfficialUpstream => {
            if client.better_auth_version != Some(COMPATIBLE_BETTER_AUTH_VERSION) {
                return Err(format!(
                    "plugin '{plugin_id}' official upstream client must target Better Auth {COMPATIBLE_BETTER_AUTH_VERSION}"
                ));
            }
        }
        PluginClientProvenance::Application => {
            if client.better_auth_version.is_some() {
                return Err(format!(
                    "plugin '{plugin_id}' application client cannot claim a Better Auth version"
                ));
            }
        }
    }
    Ok(())
}
