use crate::scim::ScimScope;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimManagedConnection {
    #[serde(skip)]
    pub id: String,
    pub creation_request_id: String,
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub status: String,
    #[serde(skip)]
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub decommission_started_at: Option<DateTime<Utc>>,
    pub decommission_started_by: Option<String>,
    pub decommissioned_at: Option<DateTime<Utc>>,
    pub decommissioned_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimManagedCredential {
    #[serde(skip)]
    pub id: String,
    #[serde(skip)]
    pub connection_record_id: String,
    pub credential_id: String,
    #[serde(skip_serializing)]
    pub token_digest: String,
    #[serde(skip)]
    pub hash_version: String,
    pub status: String,
    pub scopes: Vec<ScimScope>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimManagedConnectionEvent {
    #[serde(skip)]
    pub id: String,
    #[serde(skip)]
    pub connection_record_id: String,
    pub sequence: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub actor_id: String,
    pub credential_id: Option<String>,
    pub created_at: DateTime<Utc>,
}
