use super::{error::Result, support::emit};
use crate::{
    AgentAuthAuditEventType, AgentAuthEventFields, AgentDefaultHostCapabilitiesContext,
    AgentEndpointContext, AgentGrantStatus, AgentHost, AgentHostStatus, AgentIdentity, AgentMode,
    AgentStatus, agent_auth::axum::AgentAuthState,
};
use chrono::{DateTime, Utc};
use serde_json::{Map, json};
use std::collections::HashSet;
#[cfg(test)]
use uuid::Uuid;

pub(super) struct PendingActivation {
    pub expected_agents: Vec<AgentIdentity>,
    pub expected_grants: Vec<crate::AgentCapabilityGrant>,
    pub agent_updates: Vec<AgentIdentity>,
    pub grant_updates: Vec<crate::AgentCapabilityGrant>,
    pub host_update: AgentHost,
    pub previous_user_id: Option<String>,
    claimed: Vec<(AgentIdentity, Vec<String>)>,
    revoked_ids: Vec<String>,
}

pub(super) async fn prepare(
    state: &AgentAuthState,
    host: Option<&AgentHost>,
    current_agent_id: &str,
    user_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<PendingActivation>> {
    let Some(host) = host.filter(|host| host.user_id.as_deref() != Some(user_id)) else {
        return Ok(None);
    };
    let (expected_agents, expected_grants) = load_related(state, host, current_agent_id).await?;
    let defaults = resolve_defaults(state, host, user_id).await;
    Ok(Some(build(
        host,
        user_id,
        now,
        expected_agents,
        expected_grants,
        defaults,
    )))
}

async fn load_related(
    state: &AgentAuthState,
    host: &AgentHost,
    current_agent_id: &str,
) -> Result<(Vec<AgentIdentity>, Vec<crate::AgentCapabilityGrant>)> {
    let agents = state
        .store
        .list_agents_for_host(&host.id)
        .await?
        .into_iter()
        .filter(|agent| agent.id != current_agent_id)
        .collect::<Vec<_>>();
    let mut grants = Vec::new();
    for agent in &agents {
        grants.extend(state.store.list_grants(&agent.id).await?);
    }
    Ok((agents, grants))
}

async fn resolve_defaults(state: &AgentAuthState, host: &AgentHost, user_id: &str) -> Vec<String> {
    match &state.config.resolve_default_host_capabilities {
        Some(resolver) => {
            resolver
                .resolve(AgentDefaultHostCapabilitiesContext {
                    endpoint: endpoint(),
                    mode: AgentMode::Delegated,
                    user_id: Some(user_id.to_owned()),
                    host_id: Some(host.id.clone()),
                    host_name: host.name.clone(),
                })
                .await
        }
        None => state.config.default_host_capabilities.clone(),
    }
}

fn build(
    host: &AgentHost,
    user_id: &str,
    now: DateTime<Utc>,
    expected_agents: Vec<AgentIdentity>,
    expected_grants: Vec<crate::AgentCapabilityGrant>,
    default_capabilities: Vec<String>,
) -> PendingActivation {
    let previous_user_id = host.user_id.clone();
    let mut agent_updates = expected_agents.clone();
    let mut revoked_ids = Vec::new();
    if let Some(previous_user_id) = previous_user_id.as_deref() {
        for agent in &mut agent_updates {
            if agent.user_id.as_deref() == Some(previous_user_id)
                && !matches!(agent.status, AgentStatus::Revoked | AgentStatus::Rejected)
            {
                agent.status = AgentStatus::Revoked;
                agent.updated_at = now;
                revoked_ids.push(agent.id.clone());
            }
        }
    }
    let mut claimed = Vec::new();
    for agent in &mut agent_updates {
        if agent.mode == AgentMode::Autonomous && agent.status == AgentStatus::Active {
            let capabilities = expected_grants
                .iter()
                .filter(|grant| {
                    grant.agent_id == agent.id && grant.status == AgentGrantStatus::Active
                })
                .map(|grant| grant.capability.clone())
                .collect();
            agent.status = AgentStatus::Claimed;
            agent.user_id = Some(user_id.to_owned());
            agent.updated_at = now;
            claimed.push((agent.clone(), capabilities));
        }
    }
    let affected = agent_updates
        .iter()
        .filter(|agent| {
            revoked_ids.contains(&agent.id)
                || claimed.iter().any(|(claimed, _)| claimed.id == agent.id)
        })
        .map(|agent| agent.id.clone())
        .collect::<HashSet<_>>();
    let grant_updates = expected_grants
        .iter()
        .filter(|grant| affected.contains(&grant.agent_id))
        .cloned()
        .map(|mut grant| {
            grant.status = AgentGrantStatus::Revoked;
            grant.updated_at = now;
            grant
        })
        .collect();
    agent_updates.retain(|agent| affected.contains(&agent.id));
    let mut host_update = host.clone();
    host_update.user_id = Some(user_id.to_owned());
    host_update.status = AgentHostStatus::Active;
    host_update.activated_at = Some(now);
    host_update.updated_at = now;
    host_update.default_capabilities = default_capabilities;
    PendingActivation {
        expected_agents,
        expected_grants,
        agent_updates,
        grant_updates,
        host_update,
        previous_user_id,
        claimed,
        revoked_ids,
    }
}

pub(super) async fn after_commit(
    state: &AgentAuthState,
    activation: &PendingActivation,
    user_id: &str,
) {
    for agent_id in &activation.revoked_ids {
        emit(
            &state.config,
            AgentAuthAuditEventType::AgentRevoked,
            AgentAuthEventFields {
                actor_id: Some(user_id.to_string()),
                agent_id: Some(agent_id.clone()),
                host_id: Some(activation.host_update.id.clone()),
                metadata: Some(Map::from_iter([(
                    "reason".into(),
                    json!("host_transferred"),
                )])),
                ..AgentAuthEventFields::default()
            },
        )
        .await;
    }
    for (agent, capabilities) in &activation.claimed {
        if let Some(callback) = &state.config.on_autonomous_agent_claimed {
            callback
                .call(crate::AgentAutonomousClaimedContext {
                    endpoint: endpoint(),
                    agent: agent.clone(),
                    host: activation.host_update.clone(),
                    user_id: user_id.to_owned(),
                    capabilities: capabilities.clone(),
                })
                .await;
        }
        emit(
            &state.config,
            AgentAuthAuditEventType::AgentClaimed,
            AgentAuthEventFields {
                actor_id: Some(user_id.to_string()),
                agent_id: Some(agent.id.clone()),
                host_id: Some(activation.host_update.id.clone()),
                metadata: Some(Map::from_iter([(
                    "capabilities".into(),
                    json!(capabilities),
                )])),
                ..AgentAuthEventFields::default()
            },
        )
        .await;
    }
    if let Some(callback) = &state.config.on_host_claimed {
        callback
            .call(crate::AgentHostClaimedContext {
                endpoint: endpoint(),
                host_id: activation.host_update.id.clone(),
                user_id: user_id.to_owned(),
                previous_user_id: activation.previous_user_id.clone(),
            })
            .await;
    }
    emit(
        &state.config,
        AgentAuthAuditEventType::HostClaimed,
        AgentAuthEventFields {
            actor_id: Some(user_id.to_string()),
            host_id: Some(activation.host_update.id.clone()),
            metadata: Some(Map::from_iter([(
                "previousUserId".into(),
                json!(activation.previous_user_id),
            )])),
            ..AgentAuthEventFields::default()
        },
    )
    .await;
}

fn endpoint() -> AgentEndpointContext {
    AgentEndpointContext {
        method: "POST".into(),
        path: "/agent/approve-capability".into(),
        ..AgentEndpointContext::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentCapabilityGrant, AgentHostStatus};

    fn host(user_id: Uuid, now: DateTime<Utc>) -> AgentHost {
        AgentHost {
            id: "host".into(),
            name: Some("Host".into()),
            user_id: Some(user_id.to_string()),
            default_capabilities: vec!["old".into()],
            public_key: None,
            kid: None,
            jwks_url: None,
            enrollment_token_hash: None,
            enrollment_token_expires_at: None,
            status: AgentHostStatus::Pending,
            activated_at: None,
            expires_at: None,
            last_used_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn agent(
        id: &str,
        user_id: Option<Uuid>,
        mode: AgentMode,
        now: DateTime<Utc>,
    ) -> AgentIdentity {
        AgentIdentity {
            id: id.into(),
            name: id.into(),
            user_id: user_id.map(|value| value.to_string()),
            host_id: "host".into(),
            status: AgentStatus::Active,
            mode,
            public_key: "{}".into(),
            kid: None,
            jwks_url: None,
            last_used_at: None,
            activated_at: Some(now),
            expires_at: None,
            metadata: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn grant(agent_id: &str, now: DateTime<Utc>) -> AgentCapabilityGrant {
        AgentCapabilityGrant {
            id: format!("grant-{agent_id}"),
            agent_id: agent_id.into(),
            capability: "mail.read".into(),
            constraints: None,
            denied_by: None,
            granted_by: None,
            expires_at: None,
            status: AgentGrantStatus::Active,
            reason: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn host_transfer_matches_pending_agent_activation_cascade() {
        let now = Utc::now();
        let old_user = Uuid::new_v4();
        let new_user = Uuid::new_v4();
        let agents = vec![
            agent("old-delegated", Some(old_user), AgentMode::Delegated, now),
            agent("autonomous", None, AgentMode::Autonomous, now),
            agent("unrelated", Some(new_user), AgentMode::Delegated, now),
        ];
        let grants = agents.iter().map(|agent| grant(&agent.id, now)).collect();
        let activation = build(
            &host(old_user, now),
            &new_user.to_string(),
            now,
            agents,
            grants,
            vec!["GET".into()],
        );
        assert_eq!(activation.previous_user_id, Some(old_user.to_string()));
        assert_eq!(activation.host_update.user_id, Some(new_user.to_string()));
        assert_eq!(activation.host_update.default_capabilities, ["GET"]);
        assert_eq!(activation.agent_updates.len(), 2);
        assert!(
            activation.agent_updates.iter().any(|agent| {
                agent.id == "old-delegated" && agent.status == AgentStatus::Revoked
            })
        );
        assert!(activation.agent_updates.iter().any(|agent| {
            agent.id == "autonomous"
                && agent.status == AgentStatus::Claimed
                && agent.user_id == Some(new_user.to_string())
        }));
        assert_eq!(activation.grant_updates.len(), 2);
        assert!(
            activation
                .grant_updates
                .iter()
                .all(|grant| grant.status == AgentGrantStatus::Revoked)
        );
    }
}
