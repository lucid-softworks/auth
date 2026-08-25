use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, fmt, str::FromStr};
use uuid::Uuid;

macro_rules! string_enum {
    ($type:ident, $error:ident, {$($variant:ident => $value:literal,)+}) => {
        impl $type {
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value,)+ }
            }
        }
        impl fmt::Display for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
        impl FromStr for $type {
            type Err = $error;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value { $($value => Ok(Self::$variant),)+ _ => Err($error(value.into())), }
            }
        }
        #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
        #[error("invalid value `{0}`")]
        pub struct $error(pub String);
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentMode {
    Delegated,
    Autonomous,
}

string_enum!(AgentMode, AgentModeParseError, {
    Delegated => "delegated",
    Autonomous => "autonomous",
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Active,
    Pending,
    Expired,
    Revoked,
    Rejected,
    Claimed,
}

string_enum!(AgentStatus, AgentStatusParseError, {
    Active => "active",
    Pending => "pending",
    Expired => "expired",
    Revoked => "revoked",
    Rejected => "rejected",
    Claimed => "claimed",
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentHostStatus {
    Active,
    Pending,
    PendingEnrollment,
    Revoked,
    Rejected,
}

string_enum!(AgentHostStatus, AgentHostStatusParseError, {
    Active => "active",
    Pending => "pending",
    PendingEnrollment => "pending_enrollment",
    Revoked => "revoked",
    Rejected => "rejected",
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentGrantStatus {
    Active,
    Pending,
    Denied,
    Revoked,
    Consumed,
}

string_enum!(AgentGrantStatus, AgentGrantStatusParseError, {
    Active => "active",
    Pending => "pending",
    Denied => "denied",
    Revoked => "revoked",
    Consumed => "consumed",
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentApprovalMethod {
    DeviceAuthorization,
    Ciba,
}

string_enum!(AgentApprovalMethod, AgentApprovalMethodParseError, {
    DeviceAuthorization => "device_authorization",
    Ciba => "ciba",
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

string_enum!(AgentApprovalStatus, AgentApprovalStatusParseError, {
    Pending => "pending",
    Approved => "approved",
    Denied => "denied",
    Expired => "expired",
});

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentHost {
    pub id: String,
    pub name: Option<String>,
    pub user_id: Option<Uuid>,
    pub default_capabilities: Vec<String>,
    pub public_key: Option<String>,
    pub kid: Option<String>,
    pub jwks_url: Option<String>,
    pub enrollment_token_hash: Option<String>,
    pub enrollment_token_expires_at: Option<DateTime<Utc>>,
    pub status: AgentHostStatus,
    pub activated_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentIdentity {
    pub id: String,
    pub name: String,
    pub user_id: Option<Uuid>,
    pub host_id: String,
    pub status: AgentStatus,
    pub mode: AgentMode,
    pub public_key: String,
    pub kid: Option<String>,
    pub jwks_url: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub activated_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<Map<String, Value>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub type AgentCapabilityConstraints = BTreeMap<String, AgentConstraintValue>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentConstraintValue {
    Primitive(AgentConstraintPrimitive),
    Operators(AgentConstraintOperators),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentConstraintPrimitive {
    String(String),
    Number(f64),
    Boolean(bool),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentConstraintOperators {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eq: Option<AgentConstraintPrimitive>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#in: Option<Vec<AgentConstraintPrimitive>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_in: Option<Vec<AgentConstraintPrimitive>>,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilityGrant {
    pub id: String,
    pub agent_id: String,
    pub capability: String,
    pub constraints: Option<AgentCapabilityConstraints>,
    pub denied_by: Option<Uuid>,
    pub granted_by: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: AgentGrantStatus,
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentApprovalRequest {
    pub id: String,
    pub method: AgentApprovalMethod,
    pub agent_id: Option<String>,
    pub host_id: Option<String>,
    pub user_id: Option<Uuid>,
    pub capabilities: Option<String>,
    pub status: AgentApprovalStatus,
    pub user_code_hash: Option<String>,
    pub login_hint: Option<String>,
    pub binding_message: Option<String>,
    pub client_notification_token: Option<String>,
    pub client_notification_endpoint: Option<String>,
    pub delivery_mode: Option<String>,
    pub interval: f64,
    pub last_polled_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
