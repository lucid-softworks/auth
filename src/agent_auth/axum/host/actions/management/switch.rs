use super::shares_organization;
use crate::{
    AgentAuthAuditEvent, AgentAuthAuditEventType, AgentAuthEvent, AgentAuthEventFields,
    AgentAutonomousClaimedContext, AgentClaimedAutonomousAgent, AgentEndpointContext,
    AgentHostClaimedContext, AgentHostStatus, AgentHostSwitchOutcome,
    agent_auth::axum::{
        AgentAuthState,
        host::error::{HostError, store_error},
    },
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

pub(in crate::agent_auth::axum::host) async fn switch_to_user(
    state: &AgentAuthState,
    user_id: &str,
    host_id: &str,
    endpoint: AgentEndpointContext,
    now: DateTime<Utc>,
) -> Result<Value, HostError> {
    let host = state
        .store
        .find_host(host_id)
        .await
        .map_err(store_error)?
        .ok_or_else(HostError::host_not_found)?;
    if host.status == AgentHostStatus::Revoked {
        return Err(HostError::host_revoked());
    }
    if let Some(owner) = host.user_id.as_deref()
        && owner != user_id
        && !shares_organization(state, user_id, owner).await
    {
        return Err(HostError::unauthorized());
    }
    let switched = state
        .store
        .switch_host_account_cascade(host_id, user_id, now)
        .await
        .map_err(store_error)?
        .ok_or_else(HostError::host_not_found)?;
    notify_claimed_agents(state, &switched, user_id, &endpoint).await;
    notify_host_claimed(state, &switched, user_id, endpoint).await;
    Ok(json!({
        "host_id": switched.host.id,
        "status": switched.host.status,
        "previous_user_id": switched.previous_user_id,
        "new_user_id": user_id,
        "agents_revoked": switched.revoked_agent_ids.len()
    }))
}

async fn notify_claimed_agents(
    state: &AgentAuthState,
    switched: &AgentHostSwitchOutcome,
    user_id: &str,
    endpoint: &AgentEndpointContext,
) {
    for claimed in &switched.claimed_agents {
        notify_claimed_agent(state, switched, claimed, user_id, endpoint).await;
    }
}

async fn notify_claimed_agent(
    state: &AgentAuthState,
    switched: &AgentHostSwitchOutcome,
    claimed: &AgentClaimedAutonomousAgent,
    user_id: &str,
    endpoint: &AgentEndpointContext,
) {
    if let Some(callback) = &state.config.on_autonomous_agent_claimed {
        callback
            .call(AgentAutonomousClaimedContext {
                endpoint: endpoint.clone(),
                agent: claimed.agent.clone(),
                host: switched.host.clone(),
                user_id: user_id.to_owned(),
                capabilities: claimed.capabilities.clone(),
            })
            .await;
    }
    super::super::super::super::events::emit(
        &state.config,
        AgentAuthEvent::Audit(Box::new(AgentAuthAuditEvent {
            r#type: AgentAuthAuditEventType::AgentClaimed,
            fields: AgentAuthEventFields {
                actor_id: Some(user_id.to_string()),
                agent_id: Some(claimed.agent.id.clone()),
                host_id: Some(switched.host.id.clone()),
                metadata: Some(serde_json::Map::from_iter([(
                    "capabilities".into(),
                    json!(claimed.capabilities),
                )])),
                ..AgentAuthEventFields::default()
            },
        })),
    );
}

async fn notify_host_claimed(
    state: &AgentAuthState,
    switched: &AgentHostSwitchOutcome,
    user_id: &str,
    endpoint: AgentEndpointContext,
) {
    let mut metadata = serde_json::Map::from_iter([
        ("newUserId".into(), json!(user_id)),
        (
            "agentsRevoked".into(),
            json!(switched.revoked_agent_ids.len()),
        ),
    ]);
    if let Some(previous_user_id) = switched.previous_user_id.as_ref() {
        metadata.insert("previousUserId".into(), json!(previous_user_id));
    }
    super::super::super::events::emit(
        state,
        AgentAuthAuditEventType::HostClaimed,
        Some(user_id.to_string()),
        None,
        switched.host.id.clone(),
        metadata,
    );
    if let Some(callback) = &state.config.on_host_claimed {
        callback
            .call(AgentHostClaimedContext {
                endpoint,
                host_id: switched.host.id.clone(),
                user_id: user_id.to_owned(),
                previous_user_id: switched.previous_user_id.clone(),
            })
            .await;
    }
}
