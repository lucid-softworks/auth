use super::support::{origin, sanitize};
use crate::{
    AgentCapabilityGrant, AgentGrantStatus, AgentIdentity, AgentMode, AgentStatus,
    agent_auth::axum::{
        AgentAuthState,
        agent::{
            approval::{self, ApprovalInput},
            bootstrap,
            error::AgentError,
            grants,
            model::ClaimBody,
        },
    },
};
use axum::http::{HeaderMap, StatusCode};
use serde_json::{Value, json};

pub(super) async fn claim_inner(
    state: &AgentAuthState,
    headers: &HeaderMap,
    base_url: &str,
    body: ClaimBody,
) -> Result<Value, AgentError> {
    let _caller = bootstrap::verify(
        state,
        headers,
        base_url,
        "/agent/claim",
        AgentMode::Delegated,
        None,
    )
    .await?;
    let (agent, all_grants, active) = claimable_target(state, &body.agent_id).await?;
    let approval = approval::create(
        &state.store,
        &state.config,
        ApprovalInput {
            origin: &origin(base_url),
            agent_id: &agent.id,
            agent_name: &agent.name,
            host_id: &agent.host_id,
            user_id: None,
            capabilities: &active,
            preferred_method: body.preferred_method.as_deref(),
            login_hint: body.login_hint.as_deref(),
            binding_message: Some(
                body.binding_message
                    .map(|message| sanitize(&message, 500))
                    .unwrap_or_else(|| format!("Claim autonomous agent \"{}\"", agent.name)),
            ),
        },
    )
    .await?;
    Ok(json!({
        "agent_id":agent.id,
        "host_id":agent.host_id,
        "name":agent.name,
        "mode":agent.mode,
        "status":agent.status,
        "agent_capability_grants":grants::format(all_grants, &state.config),
        "approval":approval
    }))
}

async fn claimable_target(
    state: &AgentAuthState,
    agent_id: &str,
) -> Result<(AgentIdentity, Vec<AgentCapabilityGrant>, Vec<String>), AgentError> {
    let agent = state
        .store
        .find_agent(agent_id)
        .await
        .map_err(AgentError::store)?
        .ok_or_else(AgentError::not_found)?;
    if agent.mode != AgentMode::Autonomous {
        return Err(AgentError::bad(
            "unsupported_mode",
            "Only autonomous agents can be claimed.",
        ));
    }
    if agent.status == AgentStatus::Claimed {
        return Err(AgentError::new(
            StatusCode::CONFLICT,
            "agent_claimed",
            "This agent has already been claimed.",
        ));
    }
    if agent.status != AgentStatus::Active {
        return Err(AgentError::bad(
            "agent_not_found",
            "Agent is not available for claiming.",
        ));
    }
    let host = state
        .store
        .find_host(&agent.host_id)
        .await
        .map_err(AgentError::store)?
        .ok_or_else(|| {
            AgentError::new(StatusCode::NOT_FOUND, "host_not_found", "Host not found")
        })?;
    if host.user_id.is_some() {
        return Err(AgentError::new(
            StatusCode::CONFLICT,
            "agent_claimed",
            "This agent's host is already owned by a user.",
        ));
    }
    let all_grants = state
        .store
        .list_grants(&agent.id)
        .await
        .map_err(AgentError::store)?;
    let active = all_grants
        .iter()
        .filter(|grant| grant.status == AgentGrantStatus::Active)
        .map(|grant| grant.capability.clone())
        .collect();
    Ok((agent, all_grants, active))
}
