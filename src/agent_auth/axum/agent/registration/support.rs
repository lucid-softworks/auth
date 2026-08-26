use crate::{
    AgentCapabilityGrant, AgentCapabilityRequest, AgentGrantStatus, AgentGrantTtlContext,
    AgentIdentity,
    agent_auth::{
        axum::{AgentAuthState, agent::error::AgentError},
        policy::{find_blocked_capabilities, has_capability},
    },
};
use chrono::{Duration as ChronoDuration, Utc};
use serde_json::Value;
use uuid::Uuid;

pub(in crate::agent_auth::axum::agent) async fn build_grants(
    state: &AgentAuthState,
    agent: &AgentIdentity,
    requests: &[AgentCapabilityRequest],
    active: &[String],
    pending: &[String],
    reason: Option<&str>,
    now: chrono::DateTime<Utc>,
) -> Result<Vec<AgentCapabilityGrant>, AgentError> {
    let mut grants = Vec::new();
    for (capability, status) in active
        .iter()
        .map(|name| (name, AgentGrantStatus::Active))
        .chain(pending.iter().map(|name| (name, AgentGrantStatus::Pending)))
    {
        let constraints = requests
            .iter()
            .find(|request| request.name() == capability)
            .and_then(AgentCapabilityRequest::constraints)
            .cloned();
        let expires_at = if status == AgentGrantStatus::Active {
            match &state.config.resolve_grant_ttl {
                Some(resolve) => resolve
                    .resolve(AgentGrantTtlContext {
                        capability: capability.clone(),
                        agent_id: agent.id.clone(),
                        host_id: Some(agent.host_id.clone()),
                        user_id: agent.user_id.clone(),
                    })
                    .await
                    .map(|ttl| now + duration(ttl)),
                None => state
                    .config
                    .capabilities
                    .iter()
                    .find(|definition| definition.name == *capability)
                    .and_then(|definition| definition.grant_ttl)
                    .map(|ttl| now + duration(ttl)),
            }
        } else {
            None
        };
        grants.push(AgentCapabilityGrant {
            id: Uuid::new_v4().to_string(),
            agent_id: agent.id.clone(),
            capability: capability.clone(),
            constraints,
            denied_by: None,
            granted_by: agent.user_id.clone(),
            expires_at,
            status,
            reason: reason.map(|reason| sanitize(reason, 500)),
            created_at: now,
            updated_at: now,
        });
    }
    Ok(grants)
}

pub(super) fn budget(defaults: &[String], requested: &[String]) -> (Vec<String>, Vec<String>) {
    if !defaults.is_empty() {
        if requested.is_empty() {
            return (defaults.to_vec(), Vec::new());
        }
        return requested
            .iter()
            .cloned()
            .partition(|capability| has_capability(defaults, capability));
    }
    if requested.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        (Vec::new(), requested.to_vec())
    }
}

pub(super) async fn validate_capabilities(
    state: &AgentAuthState,
    capabilities: Vec<String>,
) -> Result<(), AgentError> {
    let blocked = find_blocked_capabilities(&capabilities, &state.config.blocked_capabilities);
    let unknown: Vec<_> = capabilities
        .iter()
        .filter(|name| {
            !state.config.capabilities.is_empty()
                && !state
                    .config
                    .capabilities
                    .iter()
                    .any(|definition| definition.name == name.as_str())
        })
        .cloned()
        .collect();
    if !blocked.is_empty() || !unknown.is_empty() {
        return Err(AgentError::bad(
            "invalid_capabilities",
            "One or more requested capability names don't exist or are blocked",
        ));
    }
    if let Some(validate) = &state.config.validate_capabilities
        && !validate.validate(capabilities).await
    {
        return Err(AgentError::bad(
            "invalid_capabilities",
            "One or more requested capability names don't exist or are blocked",
        ));
    }
    Ok(())
}

pub(super) fn validate_required_constraints(
    requests: &[AgentCapabilityRequest],
    state: &AgentAuthState,
) -> Result<(), AgentError> {
    for request in requests {
        let Some(definition) = state
            .config
            .capabilities
            .iter()
            .find(|definition| definition.name == request.name())
        else {
            continue;
        };
        for required in definition
            .required_constraints
            .as_deref()
            .unwrap_or_default()
        {
            if request
                .constraints()
                .is_none_or(|constraints| !constraints.contains_key(required))
            {
                return Err(AgentError::bad(
                    "invalid_capabilities",
                    format!(
                        "Capability '{}' requires constraint '{required}'",
                        request.name()
                    ),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_key(key: &Value, allowed: &[String]) -> Result<(), AgentError> {
    let object = key.as_object().ok_or_else(|| {
        AgentError::bad("invalid_public_key", "Public key is invalid or malformed")
    })?;
    if !object.get("kty").is_some_and(Value::is_string)
        || !object.get("x").is_some_and(Value::is_string)
    {
        return Err(AgentError::bad(
            "invalid_public_key",
            "Public key is invalid or malformed",
        ));
    }
    let algorithm = object
        .get("crv")
        .or_else(|| object.get("kty"))
        .and_then(Value::as_str)
        .unwrap_or("undefined");
    if !allowed.iter().any(|allowed| allowed == algorithm) {
        return Err(AgentError::bad(
            "unsupported_algorithm",
            format!(
                "Key algorithm \"{algorithm}\" is not allowed. Accepted: {}",
                allowed.join(", ")
            ),
        ));
    }
    Ok(())
}

pub(super) fn sanitize(value: &str, limit: usize) -> String {
    let mut output = String::new();
    let mut inside_tag = false;
    for character in value.chars() {
        match character {
            '<' => inside_tag = true,
            '>' if inside_tag => inside_tag = false,
            _ if !inside_tag && !character.is_control() => output.push(character),
            _ => {}
        }
    }
    output.trim().chars().take(limit).collect()
}

pub(super) fn origin(base_url: &str) -> String {
    url::Url::parse(base_url)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| base_url.to_owned())
}

pub(super) fn duration(seconds: u64) -> ChronoDuration {
    ChronoDuration::seconds(seconds.try_into().unwrap_or(i64::MAX))
}
