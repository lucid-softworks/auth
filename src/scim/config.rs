use super::ScimError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::{collections::HashSet, sync::Arc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScimScope {
    UsersRead,
    UsersWrite,
    GroupsRead,
    GroupsWrite,
}

impl ScimScope {
    pub const ALL: [Self; 4] = [
        Self::UsersRead,
        Self::UsersWrite,
        Self::GroupsRead,
        Self::GroupsWrite,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UsersRead => "scim.users.read",
            Self::UsersWrite => "scim.users.write",
            Self::GroupsRead => "scim.groups.read",
            Self::GroupsWrite => "scim.groups.write",
        }
    }
}

impl serde::Serialize for ScimScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimBearerCredential {
    pub id: String,
    pub token: String,
    pub scopes: Vec<ScimScope>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl ScimBearerCredential {
    pub fn new(id: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            token: token.into(),
            scopes: ScimScope::ALL.to_vec(),
            expires_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimConnection {
    pub id: String,
    pub provisioning_domain_id: String,
    pub credentials: Vec<ScimBearerCredential>,
}

impl ScimConnection {
    pub fn new(id: impl Into<String>, credentials: Vec<ScimBearerCredential>) -> Self {
        let id = id.into();
        Self {
            provisioning_domain_id: id.clone(),
            id,
            credentials,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimManagedConnectionOptions {
    pub credential_hash_secret: String,
    pub max_active_credentials: usize,
    pub last_used_write_interval_seconds: u64,
}

impl ScimManagedConnectionOptions {
    pub fn new(credential_hash_secret: impl Into<String>) -> Self {
        Self {
            credential_hash_secret: credential_hash_secret.into(),
            max_active_credentials: 5,
            last_used_write_interval_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimVerifiedBearer {
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub credential_id: String,
    pub scopes: Vec<ScimScope>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait ScimBearerTokenVerifier: Send + Sync {
    async fn verify(
        &self,
        token: &str,
        method: &str,
        path: &str,
        headers: &std::collections::BTreeMap<String, String>,
    ) -> Result<Option<ScimVerifiedBearer>, ScimError>;
}

#[derive(Clone, Default)]
pub struct ScimOptions {
    pub connections: Vec<ScimConnection>,
    pub authentication: Option<Arc<dyn ScimBearerTokenVerifier>>,
    pub managed_connections: Option<ScimManagedConnectionOptions>,
    pub microsoft_entra_legacy_group_schema: bool,
}

impl std::fmt::Debug for ScimOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScimOptions")
            .field("connections", &self.connections)
            .field("authentication", &self.authentication.is_some())
            .field("managed_connections", &self.managed_connections)
            .field(
                "microsoft_entra_legacy_group_schema",
                &self.microsoft_entra_legacy_group_schema,
            )
            .finish()
    }
}

impl ScimOptions {
    pub fn validate(&self) -> Result<(), String> {
        if self.connections.is_empty()
            && self.authentication.is_none()
            && self.managed_connections.is_none()
        {
            return Err(
                "The scim plugin requires a provisioning connection, bearer token verifier, or managed connection catalog."
                    .into(),
            );
        }
        if let Some(managed) = &self.managed_connections {
            if managed.credential_hash_secret.chars().count() < 32 {
                return Err(
                    "SCIM managed credentialHashSecret must contain at least 32 characters."
                        .into(),
                );
            }
            if !(1..=100).contains(&managed.max_active_credentials) {
                return Err(
                    "SCIM managed maxActiveCredentials must be an integer between 1 and 100."
                        .into(),
                );
            }
        }
        let mut connection_ids = HashSet::new();
        let mut tokens = HashSet::new();
        for connection in &self.connections {
            validate_identifier(&connection.id, "SCIM connection ids")?;
            if connection.id.starts_with("ba_scim_connection_") {
                return Err(
                    "Static SCIM connection ids cannot use the reserved \"ba_scim_connection_\" prefix."
                        .into(),
                );
            }
            validate_identifier(
                &connection.provisioning_domain_id,
                "SCIM provisioning domain ids",
            )?;
            if !connection_ids.insert(connection.id.as_str()) {
                return Err("SCIM connection ids must be unique.".into());
            }
            if connection.credentials.is_empty() && self.authentication.is_none() {
                return Err(
                    "SCIM connections require a static credential or bearer token verifier."
                        .into(),
                );
            }
            let mut credential_ids = HashSet::new();
            for credential in &connection.credentials {
                validate_identifier(&credential.id, "SCIM credential ids")?;
                if !credential_ids.insert(credential.id.as_str()) {
                    return Err(
                        "SCIM credential ids must be unique within a connection.".into(),
                    );
                }
                if credential.token.is_empty()
                    || credential.token.chars().any(char::is_whitespace)
                {
                    return Err("SCIM bearer tokens cannot be empty or contain whitespace.".into());
                }
                if !tokens.insert(credential.token.as_str()) {
                    return Err("SCIM bearer tokens must be unique.".into());
                }
                if credential.scopes.is_empty()
                    || credential.scopes.iter().collect::<HashSet<_>>().len()
                        != credential.scopes.len()
                {
                    return Err(
                        "SCIM credential scopes must be non-empty, unique, and supported.".into(),
                    );
                }
            }
        }
        Ok(())
    }
}

fn validate_identifier(value: &str, subject: &str) -> Result<(), String> {
    if value.is_empty() || value.chars().count() > 255 || value.trim() != value {
        Err(format!(
            "{subject} must be trimmed and contain between 1 and 255 characters."
        ))
    } else {
        Ok(())
    }
}
