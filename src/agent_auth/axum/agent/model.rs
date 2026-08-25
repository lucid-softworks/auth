use crate::{AgentCapabilityRequest, AgentMode, AgentStatus};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::super::input::{AgentInput, Field, FieldKind, Minimum};

const STRING: FieldKind = FieldKind::String { min: None };
const NON_EMPTY_STRING: FieldKind = FieldKind::String { min: Some(1) };
const ARRAY: FieldKind = FieldKind::CapabilityArray {
    min: None,
    max: None,
};
const RECORD: FieldKind = FieldKind::Record;
const MODES: FieldKind = FieldKind::Enum(&["delegated", "autonomous"]);

#[derive(Debug, Deserialize, Serialize)]
pub(in crate::agent_auth::axum) struct RegisterBody {
    pub(super) name: String,
    pub(super) capabilities: Option<Vec<AgentCapabilityRequest>>,
    pub(super) reason: Option<String>,
    pub(super) mode: Option<AgentMode>,
    pub(super) preferred_method: Option<String>,
    pub(super) host_name: Option<String>,
    pub(super) login_hint: Option<String>,
    pub(super) binding_message: Option<String>,
    pub(super) force_approval: Option<bool>,
}

impl AgentInput for RegisterBody {
    const FIELDS: &'static [Field] = &[
        Field::required("name", NON_EMPTY_STRING),
        Field::optional("capabilities", ARRAY),
        Field::optional("reason", STRING),
        Field::optional("mode", MODES),
        Field::optional("preferred_method", STRING),
        Field::optional("host_name", STRING),
        Field::optional("login_hint", STRING),
        Field::optional("binding_message", STRING),
        Field::optional("force_approval", FieldKind::Boolean),
    ];
}

#[derive(Debug, Default, Deserialize)]
pub(in crate::agent_auth::axum) struct ListQuery {
    pub(super) status: Option<AgentStatus>,
    pub(super) mode: Option<AgentMode>,
    pub(super) host_id: Option<String>,
    pub(super) limit: Option<f64>,
    pub(super) offset: Option<f64>,
}

impl AgentInput for ListQuery {
    const FIELDS: &'static [Field] = &[
        Field::optional(
            "status",
            FieldKind::Enum(&[
                "active", "pending", "expired", "revoked", "rejected", "claimed",
            ]),
        ),
        Field::optional("mode", MODES),
        Field::optional("host_id", STRING),
        Field::optional(
            "limit",
            FieldKind::Number {
                coerce: true,
                min: Some(Minimum::exclusive(0.0)),
            },
        ),
        Field::optional(
            "offset",
            FieldKind::Number {
                coerce: true,
                min: Some(Minimum::inclusive(0.0)),
            },
        ),
    ];
}

#[derive(Debug, Deserialize)]
pub(in crate::agent_auth::axum) struct GetQuery {
    pub(super) agent_id: String,
}

impl AgentInput for GetQuery {
    const FIELDS: &'static [Field] = &[Field::required("agent_id", STRING)];
}

#[derive(Debug, Deserialize, Serialize)]
pub(in crate::agent_auth::axum) struct UpdateBody {
    pub(super) agent_id: String,
    pub(super) name: Option<String>,
    pub(super) metadata: Option<Map<String, Value>>,
}

impl AgentInput for UpdateBody {
    const FIELDS: &'static [Field] = &[
        Field::required("agent_id", STRING),
        Field::optional("name", STRING),
        Field::optional("metadata", FieldKind::PrimitiveRecord),
    ];
}

#[derive(Debug, Deserialize, Serialize)]
pub(in crate::agent_auth::axum) struct RevokeBody {
    pub(super) agent_id: Option<String>,
}

impl AgentInput for RevokeBody {
    const FIELDS: &'static [Field] = &[Field::optional("agent_id", STRING)];
}

#[derive(Debug, Deserialize, Serialize)]
pub(in crate::agent_auth::axum) struct RotateKeyBody {
    pub(super) agent_id: String,
    pub(super) public_key: Value,
}

impl AgentInput for RotateKeyBody {
    const FIELDS: &'static [Field] = &[
        Field::required("agent_id", NON_EMPTY_STRING),
        Field::required("public_key", RECORD),
    ];
}

#[derive(Debug, Deserialize, Serialize)]
pub(in crate::agent_auth::axum) struct ReactivateBody {
    pub(super) agent_id: String,
}

impl AgentInput for ReactivateBody {
    const FIELDS: &'static [Field] = &[Field::required("agent_id", STRING)];
}

#[derive(Debug, Default, Deserialize)]
pub(in crate::agent_auth::axum) struct StatusQuery {
    pub(super) agent_id: Option<String>,
}

impl AgentInput for StatusQuery {
    const FIELDS: &'static [Field] = &[Field::optional("agent_id", STRING)];
}

#[derive(Debug, Deserialize, Serialize)]
pub(in crate::agent_auth::axum) struct ClaimBody {
    pub(super) agent_id: String,
    pub(super) preferred_method: Option<String>,
    pub(super) login_hint: Option<String>,
    pub(super) binding_message: Option<String>,
}

impl AgentInput for ClaimBody {
    const FIELDS: &'static [Field] = &[
        Field::required("agent_id", STRING),
        Field::optional("preferred_method", STRING),
        Field::optional("login_hint", STRING),
        Field::optional("binding_message", STRING),
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_schema_accepts_both_capability_wire_forms() {
        let body: RegisterBody = serde_json::from_value(serde_json::json!({
            "name":"mailer",
            "capabilities":["mail.read", {"name":"mail.send", "constraints":{"account":"work"}}],
            "mode":"delegated",
            "force_approval":true
        }))
        .unwrap();
        assert_eq!(body.capabilities.unwrap().len(), 2);
        assert_eq!(body.mode, Some(AgentMode::Delegated));
    }

    #[test]
    fn metadata_schema_preserves_primitive_null_values() {
        let body: UpdateBody = serde_json::from_value(serde_json::json!({
            "agent_id":"agent-1",
            "metadata":{"text":"yes", "count":2, "enabled":true, "empty":null}
        }))
        .unwrap();
        assert_eq!(body.metadata.unwrap().len(), 4);
    }
}
