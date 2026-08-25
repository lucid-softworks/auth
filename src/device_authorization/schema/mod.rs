mod migration;
mod resolution;

pub(crate) use resolution::ResolvedDeviceAuthorizationSchema;

use crate::PluginMigration;
use std::collections::BTreeMap;

pub(crate) const STANDALONE_FIELDS: &[(&str, &str, &str)] = &[
    ("deviceCode", "device_code", "TEXT NOT NULL UNIQUE"),
    ("userCode", "user_code", "TEXT NOT NULL UNIQUE"),
    ("userId", "user_id", "UUID"),
    ("expiresAt", "expires_at", "TIMESTAMPTZ NOT NULL"),
    ("status", "status", "TEXT NOT NULL"),
    ("lastPolledAt", "last_polled_at", "TIMESTAMPTZ"),
    ("pollingInterval", "polling_interval", "DOUBLE PRECISION"),
    ("clientId", "client_id", "TEXT"),
    ("scope", "scope", "TEXT"),
];

pub(crate) const OAUTH_FIELDS: &[(&str, &str, &str)] = &[
    ("resources", "resources", "TEXT[]"),
    ("oauthClientId", "oauth_client_id", "TEXT"),
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceAuthorizationModelSchema {
    pub model_name: Option<String>,
    /// Better Auth standalone field name to adapter column name.
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceAuthorizationSchema {
    pub device_code: DeviceAuthorizationModelSchema,
}

pub(crate) fn migration(
    schema: &DeviceAuthorizationSchema,
    oauth_mode: bool,
) -> Result<PluginMigration, super::DeviceAuthorizationConfigError> {
    let resolved = ResolvedDeviceAuthorizationSchema::new(schema, oauth_mode)?;
    let default =
        ResolvedDeviceAuthorizationSchema::new(&DeviceAuthorizationSchema::default(), oauth_mode)?;
    let kind = if oauth_mode { "oauth" } else { "standalone" };
    let id = if resolved.fingerprint() == default.fingerprint() {
        format!("better-auth-device-authorization-{kind}-schema")
    } else {
        format!(
            "better-auth-device-authorization-{kind}-schema-{}",
            resolved.fingerprint()
        )
    };
    Ok(PluginMigration::owned(
        id,
        "Better Auth 1.7.1 Device Authorization schema",
        resolved.migration_sql(),
    ))
}
