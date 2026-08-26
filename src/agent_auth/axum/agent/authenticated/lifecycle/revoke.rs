use crate::agent_auth::axum::{
    AgentAuthState,
    agent::{error::AgentError, events, model::RevokeBody},
    auth,
};
use chrono::Utc;
use serde_json::{Value, json};

pub(in crate::agent_auth::axum::agent::authenticated) async fn revoke_authorized(
    state: &AgentAuthState,
    authentication: auth::ScopedAgentAuthentication,
    user_id: Option<String>,
    body: RevokeBody,
) -> Result<Value, AgentError> {
    let actor_id = match &authentication {
        auth::ScopedAgentAuthentication::Agent(session) => Some(session.user.id.clone()),
        auth::ScopedAgentAuthentication::Host(session) => session.host.user_id.clone(),
        auth::ScopedAgentAuthentication::NotApplicable => user_id.clone(),
    };
    let agent = authorized_agent(state, &authentication, user_id, &body).await?;
    let now = Utc::now();
    let outcome = state
        .store
        .revoke_agent_cascade(&agent.id, now)
        .await
        .map_err(AgentError::store)?
        .ok_or_else(AgentError::not_found)?;
    events::emit(
        state,
        crate::AgentAuthAuditEventType::AgentRevoked,
        actor_id,
        None,
        Some(outcome.agent.id.clone()),
        Some(outcome.agent.host_id.clone()),
        None,
    )
    .await;
    Ok(json!({"agent_id": outcome.agent.id, "status": "revoked"}))
}

async fn authorized_agent(
    state: &AgentAuthState,
    authentication: &auth::ScopedAgentAuthentication,
    user_id: Option<String>,
    body: &RevokeBody,
) -> Result<crate::AgentIdentity, AgentError> {
    let session_agent = match authentication {
        auth::ScopedAgentAuthentication::Agent(session) => Some(session.agent_id.as_str()),
        _ => None,
    };
    if matches!(
        authentication,
        auth::ScopedAgentAuthentication::NotApplicable
    ) && user_id.is_none()
    {
        return Err(AgentError::unauthorized_session());
    }
    let agent_id = body
        .agent_id
        .as_deref()
        .or(session_agent)
        .ok_or_else(|| AgentError::bad("invalid_request", "Invalid request"))?;
    let agent = state
        .store
        .find_agent(agent_id)
        .await
        .map_err(AgentError::store)?
        .ok_or_else(AgentError::not_found)?;
    match authentication {
        auth::ScopedAgentAuthentication::Agent(session) if session.agent_id != agent.id => {
            Err(AgentError::unauthorized())
        }
        auth::ScopedAgentAuthentication::Host(session) if session.host.id != agent.host_id => {
            Err(AgentError::unauthorized())
        }
        auth::ScopedAgentAuthentication::NotApplicable => {
            let host_owner = state
                .store
                .find_host(&agent.host_id)
                .await
                .map_err(AgentError::store)?
                .and_then(|host| host.user_id);
            if agent.user_id != user_id && host_owner != user_id {
                Err(AgentError::unauthorized())
            } else {
                Ok(agent)
            }
        }
        _ => Ok(agent),
    }
}
