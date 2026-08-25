use crate::{PluginClientMetadata, protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION};

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
    if client.better_auth_version != COMPATIBLE_BETTER_AUTH_VERSION {
        return Err(format!(
            "plugin '{plugin_id}' targets Better Auth {}, expected {}",
            client.better_auth_version, COMPATIBLE_BETTER_AUTH_VERSION
        ));
    }
    Ok(())
}
