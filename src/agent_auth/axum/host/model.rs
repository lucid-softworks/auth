use crate::{AgentHost, AgentHostStatus};
use serde::Deserialize;
use serde_json::Value;

use super::super::input::{AgentInput, Field, FieldKind};

const STRING: FieldKind = FieldKind::String { min: None };
const NON_EMPTY_STRING: FieldKind = FieldKind::String { min: Some(1) };
const ARRAY: FieldKind = FieldKind::StringArray {
    min: None,
    max: None,
};

#[derive(Debug, Deserialize)]
pub(in crate::agent_auth::axum) struct CreateHostBody {
    pub(super) name: Option<String>,
    pub(super) public_key: Option<Value>,
    pub(super) jwks_url: Option<String>,
    pub(super) default_capabilities: Option<Vec<String>>,
}

impl AgentInput for CreateHostBody {
    const FIELDS: &'static [Field] = &[
        Field::optional("name", STRING),
        Field::optional("public_key", FieldKind::JwkRecord),
        Field::optional("jwks_url", FieldKind::Url),
        Field::optional("default_capabilities", ARRAY),
    ];
}

#[derive(Debug, Deserialize)]
pub(in crate::agent_auth::axum) struct EnrollHostBody {
    pub(super) token: String,
    pub(super) public_key: Value,
    pub(super) name: Option<String>,
}

impl AgentInput for EnrollHostBody {
    const FIELDS: &'static [Field] = &[
        Field::required("token", STRING),
        Field::required("public_key", FieldKind::JwkRecord),
        Field::optional("name", STRING),
    ];
}

#[derive(Debug, Deserialize)]
pub(in crate::agent_auth::axum) struct ListHostsQuery {
    pub(super) status: Option<AgentHostStatus>,
}

impl AgentInput for ListHostsQuery {
    const FIELDS: &'static [Field] = &[Field::optional(
        "status",
        FieldKind::Enum(&[
            "active",
            "pending",
            "pending_enrollment",
            "revoked",
            "rejected",
        ]),
    )];
}

#[derive(Debug, Deserialize)]
pub(in crate::agent_auth::axum) struct GetHostQuery {
    pub(super) host_id: String,
}

impl AgentInput for GetHostQuery {
    const FIELDS: &'static [Field] = &[Field::required("host_id", STRING)];
}

#[derive(Debug, Default, Deserialize)]
pub(in crate::agent_auth::axum) struct RevokeHostBody {
    pub(super) host_id: Option<String>,
}

impl AgentInput for RevokeHostBody {
    const FIELDS: &'static [Field] = &[Field::optional("host_id", STRING)];
    const OPTIONAL_ROOT: bool = true;
}

#[derive(Debug, Deserialize)]
pub(in crate::agent_auth::axum) struct SwitchHostAccountBody {
    pub(super) host_id: String,
}

impl AgentInput for SwitchHostAccountBody {
    const FIELDS: &'static [Field] = &[Field::required("host_id", NON_EMPTY_STRING)];
}

#[derive(Debug, Deserialize)]
pub(in crate::agent_auth::axum) struct UpdateHostBody {
    pub(super) host_id: String,
    pub(super) name: Option<String>,
    pub(super) public_key: Option<Value>,
    pub(super) jwks_url: Option<String>,
    pub(super) default_capabilities: Option<Vec<String>>,
}

impl AgentInput for UpdateHostBody {
    const FIELDS: &'static [Field] = &[
        Field::required("host_id", STRING),
        Field::optional("name", STRING),
        Field::optional("public_key", FieldKind::JwkRecord),
        Field::optional("jwks_url", FieldKind::Url),
        Field::optional("default_capabilities", ARRAY),
    ];
}

#[derive(Debug, Deserialize)]
pub(in crate::agent_auth::axum) struct RotateHostKeyBody {
    pub(super) public_key: Value,
}

impl AgentInput for RotateHostKeyBody {
    const FIELDS: &'static [Field] = &[Field::required("public_key", FieldKind::JwkRecord)];
}

#[derive(Debug)]
pub(super) enum HostAuthorization {
    Host(Box<AgentHost>),
    User(String),
}
