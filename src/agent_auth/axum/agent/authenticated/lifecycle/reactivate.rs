use super::status::agent_detail;
use crate::{
    AgentGrantStatus, AgentHostSession, AgentIdentity, AgentStatus,
    agent_auth::axum::{
        AgentAuthState,
        agent::{error::AgentError, events},
    },
};
use axum::http::StatusCode;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::{Value, json};

pub(in crate::agent_auth::axum::agent::authenticated) async fn reactivate_for_host(
    state: &AgentAuthState,
    host_session: &AgentHostSession,
    agent_id: &str,
    now: DateTime<Utc>,
) -> Result<Value, AgentError> {
    let mut agent = state
        .store
        .find_agent(agent_id)
        .await
        .map_err(AgentError::store)?
        .ok_or_else(AgentError::not_found)?;
    if let Some(response) = validate_state(state, host_session, &mut agent, now).await? {
        return Ok(response);
    }
    let agent = apply_reactivation(state, agent, now).await?;
    emit_reactivated(state, &agent).await?;
    agent_detail(state, agent).await
}

async fn apply_reactivation(
    state: &AgentAuthState,
    mut agent: AgentIdentity,
    now: DateTime<Utc>,
) -> Result<AgentIdentity, AgentError> {
    let host = state
        .store
        .find_host(&agent.host_id)
        .await
        .map_err(AgentError::store)?
        .filter(|host| host.status != crate::AgentHostStatus::Revoked)
        .ok_or_else(|| {
            AgentError::new(
                StatusCode::FORBIDDEN,
                "host_revoked",
                "Host has been revoked",
            )
        })?;
    let needs_approval = host.user_id.is_none() && !host.default_capabilities.is_empty();
    let active = if needs_approval {
        &[][..]
    } else {
        host.default_capabilities.as_slice()
    };
    let pending = if needs_approval {
        host.default_capabilities.as_slice()
    } else {
        &[][..]
    };
    let grants = super::super::super::registration::build_grants(
        state,
        &agent,
        &[],
        active,
        pending,
        None,
        now,
    )
    .await?;
    agent.status = if needs_approval {
        AgentStatus::Pending
    } else {
        AgentStatus::Active
    };
    agent.activated_at = (!needs_approval).then_some(now);
    agent.last_used_at = (!needs_approval).then_some(now);
    agent.expires_at = (!needs_approval && state.config.agent_session_ttl > 0)
        .then_some(now + duration(state.config.agent_session_ttl));
    agent.updated_at = now;
    state
        .store
        .reactivate_agent_replace_grants(agent, grants)
        .await
        .map_err(AgentError::store)?
        .ok_or_else(AgentError::not_found)
}

async fn emit_reactivated(state: &AgentAuthState, agent: &AgentIdentity) -> Result<(), AgentError> {
    let active_capabilities = state
        .store
        .list_grants(&agent.id)
        .await
        .map_err(AgentError::store)?
        .into_iter()
        .filter(|grant| grant.status == AgentGrantStatus::Active)
        .map(|grant| grant.capability)
        .collect::<Vec<_>>();
    events::emit(
        state,
        crate::AgentAuthAuditEventType::AgentReactivated,
        None,
        Some("agent"),
        Some(agent.id.clone()),
        Some(agent.host_id.clone()),
        Some(serde_json::Map::from_iter([(
            "capabilities".into(),
            json!(active_capabilities),
        )])),
    )
    .await;
    Ok(())
}

async fn validate_state(
    state: &AgentAuthState,
    host: &AgentHostSession,
    agent: &mut AgentIdentity,
    now: DateTime<Utc>,
) -> Result<Option<Value>, AgentError> {
    if agent.host_id != host.host.id {
        return Err(AgentError::unauthorized());
    }
    if agent.status == AgentStatus::Active {
        return agent_detail(state, agent.clone()).await.map(Some);
    }
    if agent.status != AgentStatus::Expired {
        return Err(AgentError::forbidden_status(agent.status));
    }
    if state.config.absolute_lifetime > 0
        && now >= agent.created_at + duration(state.config.absolute_lifetime)
    {
        agent.status = AgentStatus::Revoked;
        agent.public_key.clear();
        agent.kid = None;
        agent.updated_at = now;
        state
            .store
            .update_agent(agent.clone())
            .await
            .map_err(AgentError::store)?;
        return Err(AgentError::new(
            StatusCode::FORBIDDEN,
            "absolute_lifetime_exceeded",
            "Agent's absolute lifetime has elapsed",
        ));
    }
    Ok(None)
}

fn duration(seconds: u64) -> ChronoDuration {
    ChronoDuration::seconds(seconds.try_into().unwrap_or(i64::MAX))
}
