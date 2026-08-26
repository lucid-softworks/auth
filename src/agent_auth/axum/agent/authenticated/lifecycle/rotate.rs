use crate::{
    AgentHostSession, AgentKeyRotationOutcome, AgentStatus,
    agent_auth::axum::{
        AgentAuthState,
        agent::{error::AgentError, events, model::RotateKeyBody},
    },
};
use chrono::Utc;
use serde_json::{Value, json};

pub(in crate::agent_auth::axum::agent::authenticated) async fn rotate_for_host(
    state: &AgentAuthState,
    host: &AgentHostSession,
    body: RotateKeyBody,
) -> Result<Value, AgentError> {
    validate_key(&body.public_key, &state.config.allowed_key_algorithms)?;
    let mut agent = state
        .store
        .find_agent(&body.agent_id)
        .await
        .map_err(AgentError::store)?
        .ok_or_else(AgentError::not_found)?;
    if agent.status != AgentStatus::Active {
        return Err(AgentError::forbidden_status(agent.status));
    }
    if agent.host_id != host.host.id {
        return Err(AgentError::unauthorized());
    }
    let public_key = serde_json::to_string(&body.public_key)
        .map_err(|_| AgentError::bad("invalid_public_key", "Public key is invalid or malformed"))?;
    let kid = body
        .public_key
        .get("kid")
        .and_then(Value::as_str)
        .map(str::to_owned);
    agent = match state
        .store
        .rotate_agent_key(&agent.id, public_key, kid, Utc::now())
        .await
        .map_err(AgentError::store)?
    {
        AgentKeyRotationOutcome::Rotated(agent) => *agent,
        AgentKeyRotationOutcome::NotFound => return Err(AgentError::not_found()),
        AgentKeyRotationOutcome::UniqueConflict => {
            return Err(AgentError::new(
                axum::http::StatusCode::CONFLICT,
                "agent_exists",
                "An agent with this key already exists",
            ));
        }
    };
    events::emit(
        state,
        crate::AgentAuthAuditEventType::AgentKeyRotated,
        host.host.user_id.clone(),
        Some("system"),
        Some(agent.id.clone()),
        Some(agent.host_id.clone()),
        None,
    )
    .await;
    Ok(json!({"agent_id": agent.id, "status": "active"}))
}

fn validate_key(key: &Value, allowed: &[String]) -> Result<(), AgentError> {
    let object = key.as_object().ok_or_else(|| {
        AgentError::bad("invalid_public_key", "Public key is invalid or malformed")
    })?;
    let algorithm = object
        .get("crv")
        .or_else(|| object.get("kty"))
        .and_then(Value::as_str);
    if algorithm.is_none_or(|algorithm| !allowed.iter().any(|allowed| allowed == algorithm)) {
        return Err(AgentError::bad(
            "unsupported_algorithm",
            format!(
                "Key algorithm \"{}\" is not allowed. Accepted: {}",
                algorithm.unwrap_or("undefined"),
                allowed.join(", ")
            ),
        ));
    }
    Ok(())
}
