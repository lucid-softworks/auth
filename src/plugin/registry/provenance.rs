use crate::{PluginClientProvenance, PluginDescriptor, PluginProvenance};

pub(super) fn validate(descriptor: &PluginDescriptor) -> Result<(), String> {
    match descriptor.provenance {
        PluginProvenance::PinnedBetterAuthPort {
            better_auth_version,
            server,
        } => {
            if better_auth_version != crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION {
                return Err(format!(
                    "plugin '{}' port targets Better Auth {better_auth_version}, expected {}",
                    descriptor.id,
                    crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION
                ));
            }
            if [
                server.package,
                server.version,
                server.import_path,
                server.export,
            ]
            .into_iter()
            .any(|value| value.trim().is_empty())
            {
                return Err(format!(
                    "plugin '{}' requires exact upstream server artifact metadata",
                    descriptor.id
                ));
            }
            if descriptor.version != server.version {
                return Err(format!(
                    "plugin '{}' descriptor version '{}' does not match upstream server version '{}'",
                    descriptor.id, descriptor.version, server.version
                ));
            }
            if matches!(
                descriptor.client.map(|client| client.provenance),
                Some(PluginClientProvenance::Application)
            ) {
                return Err(format!(
                    "plugin '{}' pinned port cannot use an application client as conformance evidence",
                    descriptor.id
                ));
            }
        }
        PluginProvenance::LucidExtension => {
            if matches!(
                descriptor.client.map(|client| client.provenance),
                Some(PluginClientProvenance::OfficialUpstream)
            ) {
                return Err(format!(
                    "plugin '{}' lucid extension cannot claim an official upstream client",
                    descriptor.id
                ));
            }
        }
    }
    Ok(())
}
