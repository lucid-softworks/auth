use crate::{
    AuthError,
    agent_auth::{AgentApprovalRequest, AgentCapabilityGrant, AgentHost, AgentIdentity},
    postgres::{PostgresModel, PostgresWrite},
};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use sqlx::postgres::PgRow;
use std::str::FromStr;

pub(super) fn host_writes<'a>(
    model: &'a PostgresModel<'_>,
    value: &AgentHost,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    model.encode_fields([
        ("id", json!(value.id)),
        ("name", optional_string(value.name.clone())),
        ("userId", optional_string(value.user_id.clone())),
        (
            "defaultCapabilities",
            json!(encode_json(&value.default_capabilities)?),
        ),
        ("publicKey", optional_string(value.public_key.clone())),
        ("kid", optional_string(value.kid.clone())),
        ("jwksUrl", optional_string(value.jwks_url.clone())),
        (
            "enrollmentTokenHash",
            optional_string(value.enrollment_token_hash.clone()),
        ),
        (
            "enrollmentTokenExpiresAt",
            optional_date(value.enrollment_token_expires_at),
        ),
        ("status", json!(value.status.as_str())),
        ("activatedAt", optional_date(value.activated_at)),
        ("expiresAt", optional_date(value.expires_at)),
        ("lastUsedAt", optional_date(value.last_used_at)),
        ("createdAt", date(value.created_at)),
        ("updatedAt", date(value.updated_at)),
    ])
}

pub(super) fn agent_writes<'a>(
    model: &'a PostgresModel<'_>,
    value: &AgentIdentity,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    model.encode_fields([
        ("id", json!(value.id)),
        ("name", json!(value.name)),
        ("userId", optional_string(value.user_id.clone())),
        ("hostId", json!(value.host_id)),
        ("status", json!(value.status.as_str())),
        ("mode", json!(value.mode.as_str())),
        ("publicKey", json!(value.public_key)),
        ("kid", optional_string(value.kid.clone())),
        ("jwksUrl", optional_string(value.jwks_url.clone())),
        ("lastUsedAt", optional_date(value.last_used_at)),
        ("activatedAt", optional_date(value.activated_at)),
        ("expiresAt", optional_date(value.expires_at)),
        (
            "metadata",
            value
                .metadata
                .as_ref()
                .map(encode_json)
                .transpose()?
                .map_or(Value::Null, Value::String),
        ),
        ("createdAt", date(value.created_at)),
        ("updatedAt", date(value.updated_at)),
    ])
}

pub(super) fn grant_writes<'a>(
    model: &'a PostgresModel<'_>,
    value: &AgentCapabilityGrant,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    model.encode_fields([
        ("id", json!(value.id)),
        ("agentId", json!(value.agent_id)),
        ("capability", json!(value.capability)),
        (
            "constraints",
            value
                .constraints
                .as_ref()
                .map(encode_json)
                .transpose()?
                .map_or(Value::Null, Value::String),
        ),
        ("deniedBy", optional_string(value.denied_by.clone())),
        ("grantedBy", optional_string(value.granted_by.clone())),
        ("expiresAt", optional_date(value.expires_at)),
        ("status", json!(value.status.as_str())),
        ("reason", optional_string(value.reason.clone())),
        ("createdAt", date(value.created_at)),
        ("updatedAt", date(value.updated_at)),
    ])
}

pub(super) fn approval_writes<'a>(
    model: &'a PostgresModel<'_>,
    value: &AgentApprovalRequest,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    model.encode_fields([
        ("id", json!(value.id)),
        ("method", json!(value.method.as_str())),
        ("agentId", optional_string(value.agent_id.clone())),
        ("hostId", optional_string(value.host_id.clone())),
        ("userId", optional_string(value.user_id.clone())),
        ("capabilities", optional_string(value.capabilities.clone())),
        ("status", json!(value.status.as_str())),
        (
            "userCodeHash",
            optional_string(value.user_code_hash.clone()),
        ),
        ("loginHint", optional_string(value.login_hint.clone())),
        (
            "bindingMessage",
            optional_string(value.binding_message.clone()),
        ),
        (
            "clientNotificationToken",
            optional_string(value.client_notification_token.clone()),
        ),
        (
            "clientNotificationEndpoint",
            optional_string(value.client_notification_endpoint.clone()),
        ),
        ("deliveryMode", optional_string(value.delivery_mode.clone())),
        ("interval", number(value.interval)?),
        ("lastPolledAt", optional_date(value.last_polled_at)),
        ("expiresAt", date(value.expires_at)),
        ("createdAt", date(value.created_at)),
        ("updatedAt", date(value.updated_at)),
    ])
}

pub(super) fn decode_host(model: &PostgresModel<'_>, row: &PgRow) -> Result<AgentHost, AuthError> {
    let mut values = model.decode_all(row)?;
    Ok(AgentHost {
        id: required_string(&mut values, "id")?,
        name: optional_string_value(&mut values, "name")?,
        user_id: optional_string_value(&mut values, "userId")?,
        default_capabilities: parse_json_or_default(optional_string_value(
            &mut values,
            "defaultCapabilities",
        )?)?,
        public_key: optional_string_value(&mut values, "publicKey")?,
        kid: optional_string_value(&mut values, "kid")?,
        jwks_url: optional_string_value(&mut values, "jwksUrl")?,
        enrollment_token_hash: optional_string_value(&mut values, "enrollmentTokenHash")?,
        enrollment_token_expires_at: optional_date_value(&mut values, "enrollmentTokenExpiresAt")?,
        status: parse_enum(&required_string(&mut values, "status")?)?,
        activated_at: optional_date_value(&mut values, "activatedAt")?,
        expires_at: optional_date_value(&mut values, "expiresAt")?,
        last_used_at: optional_date_value(&mut values, "lastUsedAt")?,
        created_at: required_date(&mut values, "createdAt")?,
        updated_at: required_date(&mut values, "updatedAt")?,
    })
}

pub(super) fn decode_agent(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<AgentIdentity, AuthError> {
    let mut values = model.decode_all(row)?;
    Ok(AgentIdentity {
        id: required_string(&mut values, "id")?,
        name: required_string(&mut values, "name")?,
        user_id: optional_string_value(&mut values, "userId")?,
        host_id: required_string(&mut values, "hostId")?,
        status: parse_enum(&required_string(&mut values, "status")?)?,
        mode: parse_enum(&required_string(&mut values, "mode")?)?,
        public_key: required_string(&mut values, "publicKey")?,
        kid: optional_string_value(&mut values, "kid")?,
        jwks_url: optional_string_value(&mut values, "jwksUrl")?,
        last_used_at: optional_date_value(&mut values, "lastUsedAt")?,
        activated_at: optional_date_value(&mut values, "activatedAt")?,
        expires_at: optional_date_value(&mut values, "expiresAt")?,
        metadata: parse_optional_json(optional_string_value(&mut values, "metadata")?)?,
        created_at: required_date(&mut values, "createdAt")?,
        updated_at: required_date(&mut values, "updatedAt")?,
    })
}

pub(super) fn decode_grant(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<AgentCapabilityGrant, AuthError> {
    let mut values = model.decode_all(row)?;
    Ok(AgentCapabilityGrant {
        id: required_string(&mut values, "id")?,
        agent_id: required_string(&mut values, "agentId")?,
        capability: required_string(&mut values, "capability")?,
        constraints: parse_optional_json(optional_string_value(&mut values, "constraints")?)?,
        denied_by: optional_string_value(&mut values, "deniedBy")?,
        granted_by: optional_string_value(&mut values, "grantedBy")?,
        expires_at: optional_date_value(&mut values, "expiresAt")?,
        status: parse_enum(&required_string(&mut values, "status")?)?,
        reason: optional_string_value(&mut values, "reason")?,
        created_at: required_date(&mut values, "createdAt")?,
        updated_at: required_date(&mut values, "updatedAt")?,
    })
}

pub(super) fn decode_approval(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<AgentApprovalRequest, AuthError> {
    let mut values = model.decode_all(row)?;
    Ok(AgentApprovalRequest {
        id: required_string(&mut values, "id")?,
        method: parse_enum(&required_string(&mut values, "method")?)?,
        agent_id: optional_string_value(&mut values, "agentId")?,
        host_id: optional_string_value(&mut values, "hostId")?,
        user_id: optional_string_value(&mut values, "userId")?,
        capabilities: optional_string_value(&mut values, "capabilities")?,
        status: parse_enum(&required_string(&mut values, "status")?)?,
        user_code_hash: optional_string_value(&mut values, "userCodeHash")?,
        login_hint: optional_string_value(&mut values, "loginHint")?,
        binding_message: optional_string_value(&mut values, "bindingMessage")?,
        client_notification_token: optional_string_value(&mut values, "clientNotificationToken")?,
        client_notification_endpoint: optional_string_value(
            &mut values,
            "clientNotificationEndpoint",
        )?,
        delivery_mode: optional_string_value(&mut values, "deliveryMode")?,
        interval: required_number(&mut values, "interval")?,
        last_polled_at: optional_date_value(&mut values, "lastPolledAt")?,
        expires_at: required_date(&mut values, "expiresAt")?,
        created_at: required_date(&mut values, "createdAt")?,
        updated_at: required_date(&mut values, "updatedAt")?,
    })
}

fn required_string(values: &mut Map<String, Value>, field: &str) -> Result<String, AuthError> {
    match values.remove(field) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(invalid(field)),
    }
}

fn optional_string_value(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<String>, AuthError> {
    match values.remove(field) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(Value::Null) => Ok(None),
        _ => Err(invalid(field)),
    }
}

fn required_date(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<chrono::DateTime<chrono::Utc>, AuthError> {
    parse_date(&required_string(values, field)?)
}

fn optional_date_value(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, AuthError> {
    optional_string_value(values, field)?
        .map(|value| parse_date(&value))
        .transpose()
}

fn required_number(values: &mut Map<String, Value>, field: &str) -> Result<f64, AuthError> {
    values
        .remove(field)
        .and_then(|value| value.as_f64())
        .ok_or_else(|| invalid(field))
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

fn parse_date(value: &str) -> Result<chrono::DateTime<chrono::Utc>, AuthError> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&chrono::Utc))
        .map_err(storage_error)
}

fn encode_json<T: serde::Serialize>(value: &T) -> Result<String, AuthError> {
    serde_json::to_string(value).map_err(storage_error)
}

fn optional_string(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}

fn date(value: chrono::DateTime<chrono::Utc>) -> Value {
    json!(value.to_rfc3339())
}

fn optional_date(value: Option<chrono::DateTime<chrono::Utc>>) -> Value {
    value.map_or(Value::Null, date)
}

fn number(value: f64) -> Result<Value, AuthError> {
    if value.fract() == 0.0 && value >= i32::MIN as f64 && value <= i32::MAX as f64 {
        Ok(json!(value as i32))
    } else {
        Err(AuthError::Storage(
            "Agent Auth interval must be a 32-bit integer".into(),
        ))
    }
}

fn invalid(field: &str) -> AuthError {
    AuthError::Storage(format!("invalid canonical Agent Auth field `{field}`"))
}

fn storage_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(error.to_string())
}
