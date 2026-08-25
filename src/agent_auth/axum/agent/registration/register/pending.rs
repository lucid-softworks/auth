use super::super::support::{origin, sanitize};
use crate::{
    AgentIdentity,
    agent_auth::axum::{
        AgentAuthState,
        agent::{
            approval::{self, ApprovalInput},
            error::AgentError,
            grants,
            model::RegisterBody,
        },
    },
};
use serde_json::{Value, json};

pub(super) async fn pending_response(
    state: &AgentAuthState,
    base_url: &str,
    agent: AgentIdentity,
    body: &RegisterBody,
    requested: Vec<String>,
) -> Result<Value, AgentError> {
    let all_grants = state
        .store
        .list_grants(&agent.id)
        .await
        .map_err(AgentError::store)?;
    let approval = approval::create(
        &state.store,
        &state.config,
        ApprovalInput {
            origin: &origin(base_url),
            agent_id: &agent.id,
            agent_name: &agent.name,
            host_id: &agent.host_id,
            user_id: agent.user_id,
            capabilities: &requested,
            preferred_method: body.preferred_method.as_deref(),
            login_hint: body.login_hint.as_deref(),
            binding_message: body
                .binding_message
                .as_deref()
                .map(|message| sanitize(message, 500)),
        },
    )
    .await?;
    Ok(json!({
        "agent_id": agent.id,
        "host_id": agent.host_id,
        "name": agent.name,
        "mode": agent.mode,
        "status": "pending",
        "agent_capability_grants": grants::format(all_grants, &state.config),
        "approval": approval
    }))
}
