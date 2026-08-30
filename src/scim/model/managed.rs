use crate::scim::ScimScope;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimManagedConnection {
    pub id: String,
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub status: String,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimManagedCredential {
    pub id: String,
    pub connection_record_id: String,
    pub credential_id: String,
    #[serde(skip_serializing)]
    pub token_digest: String,
    pub status: String,
    pub scopes: Vec<ScimScope>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimManagedConnectionEvent {
    pub id: String,
    pub connection_record_id: String,
    pub sequence: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub actor_id: String,
    pub credential_id: Option<String>,
    pub created_at: DateTime<Utc>,
}
