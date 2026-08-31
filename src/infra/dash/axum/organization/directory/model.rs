use crate::{ScimManagedConnection, ScimManagedCredential};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DirectoryRow {
    pub id: String,
    pub organization_id: String,
    pub provider_id: String,
    pub alias_key: String,
    pub provisioning_domain_id: String,
    pub active_organization_key: String,
    pub connection_id: Option<String>,
    pub creation_request_id: String,
    pub status: String,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub created_by_actor_id: String,
    pub updated_at: DateTime<Utc>,
    pub last_actor_id: String,
    pub sso_provider_id: Option<String>,
    pub sso_provider_record_id: Option<String>,
    pub active_sso_provider_key: String,
    pub serialized_sso_pairing: Option<String>,
    pub pairing_enforced: bool,
    pub unpaired_at: Option<DateTime<Utc>>,
    pub unpaired_by: Option<String>,
    pub decommission_started_at: Option<DateTime<Utc>>,
    pub decommissioned_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

impl DirectoryRow {
    pub fn into_map(self) -> Result<Map<String, Value>, serde_json::Error> {
        let Value::Object(map) = serde_json::to_value(self)? else {
            unreachable!("directory rows serialize as objects")
        };
        Ok(map)
    }

    pub fn from_map(map: Map<String, Value>) -> Result<Self, serde_json::Error> {
        serde_json::from_value(Value::Object(map))
    }

    pub fn response(
        &self,
        base_url: &str,
        state: Option<&(ScimManagedConnection, Vec<ScimManagedCredential>)>,
    ) -> Value {
        let credentials = state
            .map(|(_, credentials)| credentials)
            .cloned()
            .unwrap_or_default();
        json!({
            "connectionId": self.connection_id,
            "organizationId": self.organization_id,
            "providerId": self.provider_id,
            "provisioningDomainId": self.provisioning_domain_id,
            "status": self.status,
            "scimEndpoint": format!("{}/scim/v2", base_url.trim_end_matches('/')),
            "credentials": credentials,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "pairing": self.pairing(),
            "pairingEnforced": self.pairing_enforced,
            "unpairedAt": self.unpaired_at,
            "unpairedBy": self.unpaired_by,
            "decommissionedAt": self.decommissioned_at,
        })
    }

    fn pairing(&self) -> Option<Value> {
        self.serialized_sso_pairing
            .as_deref()
            .and_then(|value| serde_json::from_str(value).ok())
    }
}
