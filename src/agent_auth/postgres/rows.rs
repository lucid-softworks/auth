use crate::{
    AuthError,
    agent_auth::{AgentApprovalRequest, AgentCapabilityGrant, AgentHost, AgentIdentity},
};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use sqlx::FromRow;
use std::str::FromStr;
use uuid::Uuid;

pub(super) const HOST_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("userId", "user_id"),
    ("defaultCapabilities", "default_capabilities"),
    ("publicKey", "public_key"),
    ("kid", "kid"),
    ("jwksUrl", "jwks_url"),
    ("enrollmentTokenHash", "enrollment_token_hash"),
    ("enrollmentTokenExpiresAt", "enrollment_token_expires_at"),
    ("status", "status"),
    ("activatedAt", "activated_at"),
    ("expiresAt", "expires_at"),
    ("lastUsedAt", "last_used_at"),
    ("createdAt", "created_at"),
    ("updatedAt", "updated_at"),
];

pub(super) const AGENT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("name", "name"),
    ("userId", "user_id"),
    ("hostId", "host_id"),
    ("status", "status"),
    ("mode", "mode"),
    ("publicKey", "public_key"),
    ("kid", "kid"),
    ("jwksUrl", "jwks_url"),
    ("lastUsedAt", "last_used_at"),
    ("activatedAt", "activated_at"),
    ("expiresAt", "expires_at"),
    ("metadata", "metadata"),
    ("createdAt", "created_at"),
    ("updatedAt", "updated_at"),
];

pub(super) const GRANT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("agentId", "agent_id"),
    ("capability", "capability"),
    ("constraints", "constraints"),
    ("deniedBy", "denied_by"),
    ("grantedBy", "granted_by"),
    ("expiresAt", "expires_at"),
    ("status", "status"),
    ("reason", "reason"),
    ("createdAt", "created_at"),
    ("updatedAt", "updated_at"),
];

pub(super) const APPROVAL_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("method", "method"),
    ("agentId", "agent_id"),
    ("hostId", "host_id"),
    ("userId", "user_id"),
    ("capabilities", "capabilities"),
    ("status", "status"),
    ("userCodeHash", "user_code_hash"),
    ("loginHint", "login_hint"),
    ("bindingMessage", "binding_message"),
    ("clientNotificationToken", "client_notification_token"),
    ("clientNotificationEndpoint", "client_notification_endpoint"),
    ("deliveryMode", "delivery_mode"),
    ("interval", "interval"),
    ("lastPolledAt", "last_polled_at"),
    ("expiresAt", "expires_at"),
    ("createdAt", "created_at"),
    ("updatedAt", "updated_at"),
];

#[derive(FromRow)]
pub(super) struct HostRow {
    id: String,
    name: Option<String>,
    user_id: Option<Uuid>,
    default_capabilities: Option<String>,
    public_key: Option<String>,
    kid: Option<String>,
    jwks_url: Option<String>,
    enrollment_token_hash: Option<String>,
    enrollment_token_expires_at: Option<DateTime<Utc>>,
    status: String,
    activated_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<HostRow> for AgentHost {
    type Error = AuthError;

    fn try_from(row: HostRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            name: row.name,
            user_id: row.user_id,
            default_capabilities: parse_json_or_default(row.default_capabilities)?,
            public_key: row.public_key,
            kid: row.kid,
            jwks_url: row.jwks_url,
            enrollment_token_hash: row.enrollment_token_hash,
            enrollment_token_expires_at: row.enrollment_token_expires_at,
            status: parse_enum(&row.status)?,
            activated_at: row.activated_at,
            expires_at: row.expires_at,
            last_used_at: row.last_used_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(FromRow)]
pub(super) struct AgentRow {
    id: String,
    name: String,
    user_id: Option<Uuid>,
    host_id: String,
    status: String,
    mode: String,
    public_key: String,
    kid: Option<String>,
    jwks_url: Option<String>,
    last_used_at: Option<DateTime<Utc>>,
    activated_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    metadata: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<AgentRow> for AgentIdentity {
    type Error = AuthError;

    fn try_from(row: AgentRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            name: row.name,
            user_id: row.user_id,
            host_id: row.host_id,
            status: parse_enum(&row.status)?,
            mode: parse_enum(&row.mode)?,
            public_key: row.public_key,
            kid: row.kid,
            jwks_url: row.jwks_url,
            last_used_at: row.last_used_at,
            activated_at: row.activated_at,
            expires_at: row.expires_at,
            metadata: parse_optional_json(row.metadata)?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(FromRow)]
pub(super) struct GrantRow {
    id: String,
    agent_id: String,
    capability: String,
    constraints: Option<String>,
    denied_by: Option<Uuid>,
    granted_by: Option<Uuid>,
    expires_at: Option<DateTime<Utc>>,
    status: String,
    reason: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<GrantRow> for AgentCapabilityGrant {
    type Error = AuthError;

    fn try_from(row: GrantRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            agent_id: row.agent_id,
            capability: row.capability,
            constraints: parse_optional_json(row.constraints)?,
            denied_by: row.denied_by,
            granted_by: row.granted_by,
            expires_at: row.expires_at,
            status: parse_enum(&row.status)?,
            reason: row.reason,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(FromRow)]
pub(super) struct ApprovalRow {
    id: String,
    method: String,
    agent_id: Option<String>,
    host_id: Option<String>,
    user_id: Option<Uuid>,
    capabilities: Option<String>,
    status: String,
    user_code_hash: Option<String>,
    login_hint: Option<String>,
    binding_message: Option<String>,
    client_notification_token: Option<String>,
    client_notification_endpoint: Option<String>,
    delivery_mode: Option<String>,
    interval: f64,
    last_polled_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<ApprovalRow> for AgentApprovalRequest {
    type Error = AuthError;

    fn try_from(row: ApprovalRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            method: parse_enum(&row.method)?,
            agent_id: row.agent_id,
            host_id: row.host_id,
            user_id: row.user_id,
            capabilities: row.capabilities,
            status: parse_enum(&row.status)?,
            user_code_hash: row.user_code_hash,
            login_hint: row.login_hint,
            binding_message: row.binding_message,
            client_notification_token: row.client_notification_token,
            client_notification_endpoint: row.client_notification_endpoint,
            delivery_mode: row.delivery_mode,
            interval: row.interval,
            last_polled_at: row.last_polled_at,
            expires_at: row.expires_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

pub(super) fn encode_json<T: serde::Serialize>(value: &T) -> Result<String, AuthError> {
    serde_json::to_string(value).map_err(storage_error)
}

pub(super) fn encode_optional_json<T: serde::Serialize>(
    value: &Option<T>,
) -> Result<Option<String>, AuthError> {
    value.as_ref().map(encode_json).transpose()
}

fn parse_json_or_default<T>(value: Option<String>) -> Result<T, AuthError>
where
    T: DeserializeOwned + Default,
{
    value
        .map(|value| parse_json(&value))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn parse_optional_json<T: DeserializeOwned>(value: Option<String>) -> Result<Option<T>, AuthError> {
    value.map(|value| parse_json(&value)).transpose()
}

fn parse_json<T: DeserializeOwned>(value: &str) -> Result<T, AuthError> {
    serde_json::from_str(value).map_err(storage_error)
}

fn parse_enum<T>(value: &str) -> Result<T, AuthError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    value.parse().map_err(storage_error)
}

fn storage_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_auth::{
        AgentApprovalStatus, AgentConstraintPrimitive, AgentConstraintValue, AgentGrantStatus,
        AgentHostStatus,
    };
    use std::collections::BTreeMap;

    #[test]
    fn host_row_preserves_string_thumbprint_ids_and_json_capabilities() {
        let now = Utc::now();
        let host: AgentHost = HostRow {
            id: "sha256-thumbprint".into(),
            name: None,
            user_id: None,
            default_capabilities: Some("[\"github.read\"]".into()),
            public_key: None,
            kid: None,
            jwks_url: None,
            enrollment_token_hash: None,
            enrollment_token_expires_at: None,
            status: "pending_enrollment".into(),
            activated_at: None,
            expires_at: None,
            last_used_at: None,
            created_at: now,
            updated_at: now,
        }
        .try_into()
        .unwrap();
        assert_eq!(host.id, "sha256-thumbprint");
        assert_eq!(host.default_capabilities, ["github.read"]);
        assert_eq!(host.status, AgentHostStatus::PendingEnrollment);
    }

    #[test]
    fn grant_constraints_round_trip_through_the_upstream_text_transform() {
        let constraints = BTreeMap::from([(
            "repository".into(),
            AgentConstraintValue::Primitive(AgentConstraintPrimitive::String("auth".into())),
        )]);
        let encoded = encode_optional_json(&Some(constraints.clone())).unwrap();
        let now = Utc::now();
        let grant: AgentCapabilityGrant = GrantRow {
            id: "grant-1".into(),
            agent_id: "agent-1".into(),
            capability: "github.read".into(),
            constraints: encoded,
            denied_by: None,
            granted_by: None,
            expires_at: None,
            status: "active".into(),
            reason: None,
            created_at: now,
            updated_at: now,
        }
        .try_into()
        .unwrap();
        assert_eq!(grant.constraints, Some(constraints));
        assert_eq!(grant.status, AgentGrantStatus::Active);
    }

    #[test]
    fn malformed_transforms_and_statuses_are_storage_errors() {
        assert!(parse_json::<Vec<String>>("not json").is_err());
        assert!(parse_enum::<AgentApprovalStatus>("granted").is_err());
    }

    #[test]
    fn all_field_sets_include_string_primary_ids() {
        for fields in [HOST_FIELDS, AGENT_FIELDS, GRANT_FIELDS, APPROVAL_FIELDS] {
            assert_eq!(fields.first(), Some(&("id", "id")));
        }
        assert_eq!(HOST_FIELDS.len(), 15);
        assert_eq!(AGENT_FIELDS.len(), 15);
        assert_eq!(GRANT_FIELDS.len(), 11);
        assert_eq!(APPROVAL_FIELDS.len(), 18);
    }
}
