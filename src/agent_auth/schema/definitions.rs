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
    pub default_column: &'static str,
    pub sql: &'static str,
    pub reference: Option<Reference>,
    pub index: bool,
}

pub(super) struct ModelDefinition {
    pub model: AgentAuthModel,
    pub logical_name: &'static str,
    pub default_table: &'static str,
    pub fields: &'static [FieldDefinition],
}

macro_rules! field {
    ($logical:literal, $column:literal, $sql:literal) => {
        FieldDefinition {
            logical: $logical,
            default_column: $column,
            sql: $sql,
            reference: None,
            index: false,
        }
    };
    ($logical:literal, $column:literal, $sql:literal, index) => {
        FieldDefinition {
            index: true,
            ..field!($logical, $column, $sql)
        }
    };
    ($logical:literal, $column:literal, $sql:literal, ref $reference:expr, $index:expr) => {
        FieldDefinition {
            reference: Some($reference),
            index: $index,
            ..field!($logical, $column, $sql)
        }
    };
}

const AGENT_HOST_FIELDS: &[FieldDefinition] = &[
    field!("name", "name", "TEXT"),
    field!("userId", "user_id", "UUID", ref Reference::CoreUser, true),
    field!("defaultCapabilities", "default_capabilities", "TEXT"),
    field!("publicKey", "public_key", "TEXT"),
    field!("kid", "kid", "TEXT", index),
    field!("jwksUrl", "jwks_url", "TEXT"),
    field!(
        "enrollmentTokenHash",
        "enrollment_token_hash",
        "TEXT",
        index
    ),
    field!(
        "enrollmentTokenExpiresAt",
        "enrollment_token_expires_at",
        "TIMESTAMPTZ"
    ),
    field!("status", "status", "TEXT NOT NULL DEFAULT 'active'", index),
    field!("activatedAt", "activated_at", "TIMESTAMPTZ"),
    field!("expiresAt", "expires_at", "TIMESTAMPTZ"),
    field!("lastUsedAt", "last_used_at", "TIMESTAMPTZ"),
    field!("createdAt", "created_at", "TIMESTAMPTZ NOT NULL"),
    field!("updatedAt", "updated_at", "TIMESTAMPTZ NOT NULL"),
];

const AGENT_FIELDS: &[FieldDefinition] = &[
    field!("name", "name", "TEXT NOT NULL"),
    field!("userId", "user_id", "UUID", ref Reference::CoreUser, true),
    field!(
        "hostId",
        "host_id",
        "TEXT NOT NULL",
        ref Reference::AgentAuth(AgentAuthModel::AgentHost),
        true
    ),
    field!("status", "status", "TEXT NOT NULL DEFAULT 'active'", index),
    field!("mode", "mode", "TEXT NOT NULL DEFAULT 'delegated'"),
    field!("publicKey", "public_key", "TEXT NOT NULL"),
    field!("kid", "kid", "TEXT", index),
    field!("jwksUrl", "jwks_url", "TEXT"),
    field!("lastUsedAt", "last_used_at", "TIMESTAMPTZ"),
    field!("activatedAt", "activated_at", "TIMESTAMPTZ"),
    field!("expiresAt", "expires_at", "TIMESTAMPTZ"),
    field!("metadata", "metadata", "TEXT"),
    field!("createdAt", "created_at", "TIMESTAMPTZ NOT NULL"),
    field!("updatedAt", "updated_at", "TIMESTAMPTZ NOT NULL"),
];

const AGENT_CAPABILITY_GRANT_FIELDS: &[FieldDefinition] = &[
    field!(
        "agentId",
        "agent_id",
        "TEXT NOT NULL",
        ref Reference::AgentAuth(AgentAuthModel::Agent),
        true
    ),
    field!("capability", "capability", "TEXT NOT NULL", index),
    field!("deniedBy", "denied_by", "UUID", ref Reference::CoreUser, false),
    field!("grantedBy", "granted_by", "UUID", ref Reference::CoreUser, true),
    field!("expiresAt", "expires_at", "TIMESTAMPTZ"),
    field!("createdAt", "created_at", "TIMESTAMPTZ NOT NULL"),
    field!("updatedAt", "updated_at", "TIMESTAMPTZ NOT NULL"),
    field!("status", "status", "TEXT NOT NULL DEFAULT 'active'", index),
    field!("reason", "reason", "TEXT"),
    field!("constraints", "constraints", "TEXT"),
];

const APPROVAL_REQUEST_FIELDS: &[FieldDefinition] = &[
    field!("method", "method", "TEXT NOT NULL"),
    field!(
        "agentId",
        "agent_id",
        "TEXT",
        ref Reference::AgentAuth(AgentAuthModel::Agent),
        true
    ),
    field!(
        "hostId",
        "host_id",
        "TEXT",
        ref Reference::AgentAuth(AgentAuthModel::AgentHost),
        true
    ),
    field!("userId", "user_id", "UUID", ref Reference::CoreUser, true),
    field!("capabilities", "capabilities", "TEXT"),
    field!("status", "status", "TEXT NOT NULL DEFAULT 'pending'", index),
    field!("userCodeHash", "user_code_hash", "TEXT"),
    field!("loginHint", "login_hint", "TEXT"),
    field!("bindingMessage", "binding_message", "TEXT"),
    field!(
        "clientNotificationToken",
        "client_notification_token",
        "TEXT"
    ),
    field!(
        "clientNotificationEndpoint",
        "client_notification_endpoint",
        "TEXT"
    ),
    field!("deliveryMode", "delivery_mode", "TEXT"),
    field!("interval", "interval", "DOUBLE PRECISION NOT NULL"),
    field!("lastPolledAt", "last_polled_at", "TIMESTAMPTZ"),
    field!("expiresAt", "expires_at", "TIMESTAMPTZ NOT NULL"),
    field!("createdAt", "created_at", "TIMESTAMPTZ NOT NULL"),
    field!("updatedAt", "updated_at", "TIMESTAMPTZ NOT NULL"),
];

pub(super) const DEFINITIONS: &[ModelDefinition] = &[
    ModelDefinition {
        model: AgentAuthModel::AgentHost,
        logical_name: "agentHost",
        default_table: "lucid_auth_agent_hosts",
        fields: AGENT_HOST_FIELDS,
    },
    ModelDefinition {
        model: AgentAuthModel::Agent,
        logical_name: "agent",
        default_table: "lucid_auth_agents",
        fields: AGENT_FIELDS,
    },
    ModelDefinition {
        model: AgentAuthModel::AgentCapabilityGrant,
        logical_name: "agentCapabilityGrant",
        default_table: "lucid_auth_agent_capability_grants",
        fields: AGENT_CAPABILITY_GRANT_FIELDS,
    },
    ModelDefinition {
        model: AgentAuthModel::ApprovalRequest,
        logical_name: "approvalRequest",
        default_table: "lucid_auth_agent_approval_requests",
        fields: APPROVAL_REQUEST_FIELDS,
    },
];
