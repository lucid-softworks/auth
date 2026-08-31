use crate::{
    AgentApprovalRequest, AgentCapabilityGrant, AgentCapabilityTransitionPlan, AgentHost,
    AgentIdentity, AuthError,
};
use chrono::{DateTime, Timelike, Utc};
use serde_json::{Map, Value, json};

pub(super) fn host_record(value: &AgentHost) -> Result<Map<String, Value>, AuthError> {
    object(value).and_then(|mut row| {
        json_text(&mut row, "defaultCapabilities")?;
        Ok(row)
    })
}

pub(super) fn agent_record(value: &AgentIdentity) -> Result<Map<String, Value>, AuthError> {
    object(value).and_then(|mut row| {
        json_text(&mut row, "metadata")?;
        Ok(row)
    })
}

pub(super) fn grant_record(value: &AgentCapabilityGrant) -> Result<Map<String, Value>, AuthError> {
    object(value).and_then(|mut row| {
        json_text(&mut row, "constraints")?;
        Ok(row)
    })
}

pub(super) fn approval_record(
    value: &AgentApprovalRequest,
) -> Result<Map<String, Value>, AuthError> {
    if value.interval.fract() != 0.0
        || value.interval < i32::MIN as f64
        || value.interval > i32::MAX as f64
    {
        return Err(AuthError::Storage(
            "Agent Auth interval must be a 32-bit integer".into(),
        ));
    }
    let mut row = object(value)?;
    row.insert("interval".into(), json!(value.interval as i32));
    Ok(row)
}

pub(super) fn decode_host(mut row: Map<String, Value>) -> Result<AgentHost, AuthError> {
    parse_json(&mut row, "defaultCapabilities", json!([]))?;
    decode("agentHost", row)
}

pub(super) fn decode_agent(mut row: Map<String, Value>) -> Result<AgentIdentity, AuthError> {
    parse_json(&mut row, "metadata", Value::Null)?;
    decode("agent", row)
}

pub(super) fn decode_grant(mut row: Map<String, Value>) -> Result<AgentCapabilityGrant, AuthError> {
    parse_json(&mut row, "constraints", Value::Null)?;
    decode("agentCapabilityGrant", row)
}

pub(super) fn decode_approval(row: Map<String, Value>) -> Result<AgentApprovalRequest, AuthError> {
    decode("approvalRequest", row)
}

fn object<T: serde::Serialize>(value: &T) -> Result<Map<String, Value>, AuthError> {
    match serde_json::to_value(value).map_err(storage)? {
        Value::Object(row) => Ok(row),
        _ => Err(AuthError::Storage(
            "MySQL Agent Auth record is not an object".into(),
        )),
    }
}

fn decode<T: serde::de::DeserializeOwned>(
    model: &str,
    row: Map<String, Value>,
) -> Result<T, AuthError> {
    serde_json::from_value(Value::Object(row))
        .map_err(|error| AuthError::Storage(format!("invalid MySQL {model} row: {error}")))
}

fn json_text(row: &mut Map<String, Value>, field: &str) -> Result<(), AuthError> {
    let Some(value) = row.get_mut(field) else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    *value = Value::String(serde_json::to_string(value).map_err(storage)?);
    Ok(())
}

fn parse_json(row: &mut Map<String, Value>, field: &str, fallback: Value) -> Result<(), AuthError> {
    let value = row.remove(field).unwrap_or(fallback.clone());
    let parsed = match value {
        Value::Null | Value::Bool(false) => fallback,
        Value::String(value) if value.is_empty() => fallback,
        Value::String(value) => serde_json::from_str(&value).map_err(storage)?,
        value => value,
    };
    row.insert(field.into(), parsed);
    Ok(())
}

fn storage(error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(error.to_string())
}

pub(super) fn normalize_host(mut value: AgentHost) -> AgentHost {
    value.enrollment_token_expires_at = optional_millis(value.enrollment_token_expires_at);
    value.activated_at = optional_millis(value.activated_at);
    value.expires_at = optional_millis(value.expires_at);
    value.last_used_at = optional_millis(value.last_used_at);
    value.created_at = millis(value.created_at);
    value.updated_at = millis(value.updated_at);
    value
}

pub(super) fn normalize_agent(mut value: AgentIdentity) -> AgentIdentity {
    value.last_used_at = optional_millis(value.last_used_at);
    value.activated_at = optional_millis(value.activated_at);
    value.expires_at = optional_millis(value.expires_at);
    value.created_at = millis(value.created_at);
    value.updated_at = millis(value.updated_at);
    value
}

pub(super) fn normalize_grant(mut value: AgentCapabilityGrant) -> AgentCapabilityGrant {
    value.expires_at = optional_millis(value.expires_at);
    value.created_at = millis(value.created_at);
    value.updated_at = millis(value.updated_at);
    value
}

pub(super) fn normalize_approval(mut value: AgentApprovalRequest) -> AgentApprovalRequest {
    value.last_polled_at = optional_millis(value.last_polled_at);
    value.expires_at = millis(value.expires_at);
    value.created_at = millis(value.created_at);
    value.updated_at = millis(value.updated_at);
    value
}

pub(super) fn normalize_plan(
    mut plan: AgentCapabilityTransitionPlan,
) -> AgentCapabilityTransitionPlan {
    plan.expected_agent = normalize_agent(plan.expected_agent);
    plan.expected_host = plan.expected_host.map(normalize_host);
    plan.expected_grants = plan
        .expected_grants
        .into_iter()
        .map(normalize_grant)
        .collect();
    plan.expected_approvals = plan
        .expected_approvals
        .into_iter()
        .map(normalize_approval)
        .collect();
    plan.expected_related_agents = plan
        .expected_related_agents
        .map(|values| values.into_iter().map(normalize_agent).collect());
    plan.expected_related_grants = plan
        .expected_related_grants
        .map(|values| values.into_iter().map(normalize_grant).collect());
    plan.agent_update = plan.agent_update.map(normalize_agent);
    plan.host_update = plan.host_update.map(normalize_host);
    plan.related_agents_to_update = plan
        .related_agents_to_update
        .into_iter()
        .map(normalize_agent)
        .collect();
    plan.related_grants_to_update = plan
        .related_grants_to_update
        .into_iter()
        .map(normalize_grant)
        .collect();
    plan.grants_to_create = plan
        .grants_to_create
        .into_iter()
        .map(normalize_grant)
        .collect();
    plan.grants_to_update = plan
        .grants_to_update
        .into_iter()
        .map(normalize_grant)
        .collect();
    plan.approval_to_create = plan.approval_to_create.map(normalize_approval);
    plan.approvals_to_update = plan
        .approvals_to_update
        .into_iter()
        .map(normalize_approval)
        .collect();
    plan
}

pub(super) fn millis(value: DateTime<Utc>) -> DateTime<Utc> {
    value
        .with_nanosecond(value.timestamp_subsec_millis() * 1_000_000)
        .expect("millisecond nanoseconds are valid")
}

fn optional_millis(value: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    value.map(millis)
}
