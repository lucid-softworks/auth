use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentAuthModelSchema {
    pub model_name: Option<String>,
    /// Better Auth field name to adapter column name.
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentAuthSchema {
    pub agent_host: AgentAuthModelSchema,
    pub agent: AgentAuthModelSchema,
    pub agent_capability_grant: AgentAuthModelSchema,
    pub approval_request: AgentAuthModelSchema,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AgentAuthModel {
    AgentHost,
    Agent,
    AgentCapabilityGrant,
    ApprovalRequest,
}

#[derive(Clone, Copy)]
pub(super) enum Reference {
    CoreUser,
    AgentAuth(AgentAuthModel),
}

#[derive(Clone, Copy)]
pub(super) struct FieldDefinition {
    pub logical: &'static str,
    pub reference: Option<Reference>,
    pub index: bool,
}

pub(super) struct ModelDefinition {
    pub model: AgentAuthModel,
    pub logical_name: &'static str,
    pub fields: &'static [FieldDefinition],
}

macro_rules! field {
    ($logical:literal) => {
        FieldDefinition {
            logical: $logical,
            reference: None,
            index: false,
        }
    };
    ($logical:literal, index) => {
        FieldDefinition {
            index: true,
            ..field!($logical)
        }
    };
    ($logical:literal, ref $reference:expr, $index:expr) => {
        FieldDefinition {
            reference: Some($reference),
            index: $index,
            ..field!($logical)
        }
    };
}

const AGENT_HOST_FIELDS: &[FieldDefinition] = &[
    field!("name"),
    field!("userId", ref Reference::CoreUser, true),
    field!("defaultCapabilities"),
    field!("publicKey"),
    field!("kid", index),
    field!("jwksUrl"),
    field!("enrollmentTokenHash", index),
    field!("enrollmentTokenExpiresAt"),
    field!("status", index),
    field!("activatedAt"),
    field!("expiresAt"),
    field!("lastUsedAt"),
    field!("createdAt"),
    field!("updatedAt"),
];

const AGENT_FIELDS: &[FieldDefinition] = &[
    field!("name"),
    field!("userId", ref Reference::CoreUser, true),
    field!(
        "hostId",
        ref Reference::AgentAuth(AgentAuthModel::AgentHost),
        true
    ),
    field!("status", index),
    field!("mode"),
    field!("publicKey"),
    field!("kid", index),
    field!("jwksUrl"),
    field!("lastUsedAt"),
    field!("activatedAt"),
    field!("expiresAt"),
    field!("metadata"),
    field!("createdAt"),
    field!("updatedAt"),
];

const AGENT_CAPABILITY_GRANT_FIELDS: &[FieldDefinition] = &[
    field!(
        "agentId",
        ref Reference::AgentAuth(AgentAuthModel::Agent),
        true
    ),
    field!("capability", index),
    field!("deniedBy", ref Reference::CoreUser, false),
    field!("grantedBy", ref Reference::CoreUser, true),
    field!("expiresAt"),
    field!("createdAt"),
    field!("updatedAt"),
    field!("status", index),
    field!("reason"),
    field!("constraints"),
];

const APPROVAL_REQUEST_FIELDS: &[FieldDefinition] = &[
    field!("method"),
    field!(
        "agentId",
        ref Reference::AgentAuth(AgentAuthModel::Agent),
        true
    ),
    field!(
        "hostId",
        ref Reference::AgentAuth(AgentAuthModel::AgentHost),
        true
    ),
    field!("userId", ref Reference::CoreUser, true),
    field!("capabilities"),
    field!("status", index),
    field!("userCodeHash"),
    field!("loginHint"),
    field!("bindingMessage"),
    field!("clientNotificationToken"),
    field!("clientNotificationEndpoint"),
    field!("deliveryMode"),
    field!("interval"),
    field!("lastPolledAt"),
    field!("expiresAt"),
    field!("createdAt"),
    field!("updatedAt"),
];

pub(super) const DEFINITIONS: &[ModelDefinition] = &[
    ModelDefinition {
        model: AgentAuthModel::AgentHost,
        logical_name: "agentHost",
        fields: AGENT_HOST_FIELDS,
    },
    ModelDefinition {
        model: AgentAuthModel::Agent,
        logical_name: "agent",
        fields: AGENT_FIELDS,
    },
    ModelDefinition {
        model: AgentAuthModel::AgentCapabilityGrant,
        logical_name: "agentCapabilityGrant",
        fields: AGENT_CAPABILITY_GRANT_FIELDS,
    },
    ModelDefinition {
        model: AgentAuthModel::ApprovalRequest,
        logical_name: "approvalRequest",
        fields: APPROVAL_REQUEST_FIELDS,
    },
];
