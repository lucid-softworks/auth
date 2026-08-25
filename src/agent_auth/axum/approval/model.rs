use crate::AgentCapabilityRequest;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::super::input::{AgentInput, Field, FieldKind, Minimum};

const STRING: FieldKind = FieldKind::String { min: None };
const NON_EMPTY_STRING: FieldKind = FieldKind::String { min: Some(1) };
const ARRAY: FieldKind = FieldKind::StringArray {
    min: None,
    max: None,
};
const NON_EMPTY_CAPABILITIES: FieldKind = FieldKind::CapabilityArray {
    min: Some(1),
    max: None,
};
const NON_EMPTY_STRINGS: FieldKind = FieldKind::StringArray {
    min: Some(1),
    max: None,
};

#[derive(Debug, Deserialize, Serialize)]
pub(in crate::agent_auth::axum) struct RequestCapabilityBody {
    pub capabilities: Vec<AgentCapabilityRequest>,
    pub reason: Option<String>,
    pub preferred_method: Option<String>,
    pub login_hint: Option<String>,
    pub binding_message: Option<String>,
}

impl AgentInput for RequestCapabilityBody {
    const FIELDS: &'static [Field] = &[
        Field::required("capabilities", NON_EMPTY_CAPABILITIES),
        Field::optional("reason", STRING),
        Field::optional("preferred_method", STRING),
        Field::optional("login_hint", STRING),
        Field::optional("binding_message", STRING),
    ];
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(in crate::agent_auth::axum) enum ApprovalAction {
    Approve,
    Deny,
}

#[derive(Debug, Deserialize, Serialize)]
pub(in crate::agent_auth::axum) struct ApproveCapabilityBody {
    pub agent_id: Option<String>,
    pub approval_id: Option<String>,
    pub user_code: Option<String>,
    pub action: ApprovalAction,
    pub capabilities: Option<Vec<String>>,
    pub ttl: Option<f64>,
    pub reason: Option<String>,
    pub webauthn_response: Option<Map<String, Value>>,
}

impl AgentInput for ApproveCapabilityBody {
    const FIELDS: &'static [Field] = &[
        Field::optional("agent_id", STRING),
        Field::optional("approval_id", STRING),
        Field::optional("user_code", STRING),
        Field::required("action", FieldKind::Enum(&["approve", "deny"])),
        Field::optional("capabilities", ARRAY),
        Field::optional(
            "ttl",
            FieldKind::Number {
                coerce: false,
                min: Some(Minimum::exclusive(0.0)),
            },
        ),
        Field::optional("reason", STRING),
        Field::optional("webauthn_response", FieldKind::Record),
    ];
}

#[derive(Debug, Deserialize, Serialize)]
pub(in crate::agent_auth::axum) struct GrantCapabilityBody {
    pub agent_id: String,
    pub capabilities: Vec<AgentCapabilityRequest>,
    pub ttl: Option<f64>,
}

impl AgentInput for GrantCapabilityBody {
    const FIELDS: &'static [Field] = &[
        Field::required("agent_id", STRING),
        Field::required("capabilities", NON_EMPTY_CAPABILITIES),
        Field::optional(
            "ttl",
            FieldKind::Number {
                coerce: false,
                min: Some(Minimum::exclusive(0.0)),
            },
        ),
    ];
}

#[derive(Debug, Deserialize, Serialize)]
pub(in crate::agent_auth::axum) struct RevokeCapabilityBody {
    pub agent_id: String,
    pub capabilities: Vec<String>,
}

impl AgentInput for RevokeCapabilityBody {
    const FIELDS: &'static [Field] = &[
        Field::required("agent_id", STRING),
        Field::required("capabilities", NON_EMPTY_STRINGS),
    ];
}

#[derive(Debug, Deserialize, Serialize)]
pub(in crate::agent_auth::axum) struct CibaAuthorizeBody {
    pub login_hint: String,
    pub capabilities: Option<Vec<String>>,
    pub binding_message: Option<String>,
    pub agent_id: Option<String>,
}

impl AgentInput for CibaAuthorizeBody {
    const FIELDS: &'static [Field] = &[
        Field::required("login_hint", NON_EMPTY_STRING),
        Field::optional("capabilities", ARRAY),
        Field::optional("binding_message", STRING),
        Field::optional("agent_id", STRING),
    ];
}

#[derive(Debug, Deserialize, Serialize)]
pub(in crate::agent_auth::axum) struct DeviceCodeBody {
    pub agent_id: String,
}

impl AgentInput for DeviceCodeBody {
    const FIELDS: &'static [Field] = &[Field::required("agent_id", STRING)];
}
