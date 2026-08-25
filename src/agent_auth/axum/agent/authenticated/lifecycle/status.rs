use crate::{
    AgentIdentity, AgentStatus,
    agent_auth::axum::{
        AgentAuthState,
        agent::{error::AgentError, grants},
        auth,
    },
};
use serde_json::{Value, json};

pub(in crate::agent_auth::axum::agent::authenticated) async fn status_authorized(
    state: &AgentAuthState,
    authentication: auth::ScopedAgentAuthentication,
    requested: Option<String>,
) -> Result<Value, AgentError> {
    let (agent_id, host_id) = match authentication {
        auth::ScopedAgentAuthentication::Agent(session) => (session.agent_id.clone(), None),
        auth::ScopedAgentAuthentication::Host(session) => (
            requested.ok_or_else(|| {
                AgentError::bad(
                    "invalid_request",
                    "agent_id query parameter is required when using host JWT.",
                )
            })?,
            Some(session.host.id),
        ),
        auth::ScopedAgentAuthentication::NotApplicable => {
            return Err(AgentError::unauthorized_session());
        }
    };
    let agent = state
        .store
        .find_agent(&agent_id)
        .await
        .map_err(AgentError::store)?
        .ok_or_else(AgentError::not_found)?;
    if host_id.is_some_and(|host_id| agent.host_id != host_id) {
        return Err(AgentError::unauthorized());
    }
    let approvals = state
        .store
        .list_pending_approvals_for_agent(&agent.id)
        .await
        .unwrap_or_default();
    let effective = if agent.mode == crate::AgentMode::Autonomous
        && approvals
            .iter()
            .any(|approval| approval.agent_id.as_deref() == Some(&agent.id))
    {
        AgentStatus::Pending
    } else {
        agent.status
    };
    let mut value = agent_detail(state, agent).await?;
    value["status"] = json!(effective);
    Ok(value)
}

pub(super) async fn agent_detail(
    state: &AgentAuthState,
    agent: AgentIdentity,
) -> Result<Value, AgentError> {
    let grants = state
        .store
        .list_grants(&agent.id)
        .await
        .map_err(AgentError::store)?;
    Ok(json!({
        "agent_id": agent.id,
        "host_id": agent.host_id,
        "name": agent.name,
        "status": agent.status,
        "mode": agent.mode,
        "agent_capability_grants": grants::format(grants, &state.config),
        "user_id": agent.user_id,
        "activated_at": agent.activated_at,
        "created_at": agent.created_at,
        "last_used_at": agent.last_used_at,
        "expires_at": agent.expires_at
    }))
}
