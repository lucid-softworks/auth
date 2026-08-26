use super::{MemoryAgentAuthStore, State, write};
use crate::{
    AuthError,
    agent_auth::{
        AgentClaimedAutonomousAgent, AgentGrantStatus, AgentHost, AgentHostEnrollment,
        AgentHostEnrollmentOutcome, AgentHostStatus, AgentHostSwitchOutcome, AgentMode,
        AgentStatus,
    },
};
use chrono::{DateTime, Utc};
#[cfg(test)]
use uuid::Uuid;

pub(super) fn enroll(
    store: &MemoryAgentAuthStore,
    token_hash: &str,
    enrollment: AgentHostEnrollment,
) -> Result<AgentHostEnrollmentOutcome, AuthError> {
    let mut state = write(&store.state)?;
    let Some(provisioned_id) = state
        .hosts
        .values()
        .find(|host| host.enrollment_token_hash.as_deref() == Some(token_hash))
        .map(|host| host.id.clone())
    else {
        return Ok(AgentHostEnrollmentOutcome::TokenNotFound);
    };
    let provisioned = state
        .hosts
        .get(&provisioned_id)
        .expect("host found by token");
    if provisioned.status != AgentHostStatus::PendingEnrollment {
        return Ok(AgentHostEnrollmentOutcome::HostNotPendingEnrollment);
    }
    if provisioned
        .enrollment_token_expires_at
        .is_none_or(|expires_at| expires_at <= enrollment.now)
    {
        return Ok(AgentHostEnrollmentOutcome::TokenExpired);
    }
    let existing_id = state
        .hosts
        .values()
        .find(|host| {
            host.id != provisioned_id && host.public_key.as_deref() == Some(&enrollment.public_key)
        })
        .map(|host| host.id.clone());
    if let Some(existing_id) = existing_id {
        return merge_enrollment(&mut state, &provisioned_id, &existing_id, enrollment);
    }
    let host = state
        .hosts
        .get_mut(&provisioned_id)
        .expect("provisioned host exists");
    host.public_key = Some(enrollment.public_key);
    host.kid = enrollment.kid;
    if enrollment.name.is_some() {
        host.name = enrollment.name;
    }
    host.status = AgentHostStatus::Active;
    host.activated_at = Some(enrollment.now);
    host.expires_at = enrollment.expires_at;
    host.enrollment_token_hash = None;
    host.enrollment_token_expires_at = None;
    host.updated_at = enrollment.now;
    Ok(AgentHostEnrollmentOutcome::Enrolled(Box::new(host.clone())))
}

fn merge_enrollment(
    state: &mut State,
    provisioned_id: &str,
    existing_id: &str,
    enrollment: AgentHostEnrollment,
) -> Result<AgentHostEnrollmentOutcome, AuthError> {
    let provisioned = state
        .hosts
        .get(provisioned_id)
        .expect("provisioned host exists")
        .clone();
    let existing = state
        .hosts
        .get(existing_id)
        .expect("public-key host exists");
    if existing.status == AgentHostStatus::Revoked {
        return Ok(AgentHostEnrollmentOutcome::PublicKeyHostRevoked);
    }
    if existing.user_id.is_some()
        && provisioned.user_id.is_some()
        && existing.user_id != provisioned.user_id
    {
        return Ok(AgentHostEnrollmentOutcome::HostAlreadyLinked);
    }
    let existing = state
        .hosts
        .get_mut(existing_id)
        .expect("public-key host exists");
    existing.name = enrollment
        .name
        .or(provisioned.name)
        .or(existing.name.clone());
    existing.user_id = existing.user_id.take().or(provisioned.user_id);
    existing.kid = enrollment.kid;
    existing.status = AgentHostStatus::Active;
    existing.activated_at = Some(enrollment.now);
    existing.expires_at = enrollment.expires_at;
    existing.updated_at = enrollment.now;
    let enrolled = existing.clone();
    let provisioned = state
        .hosts
        .get_mut(provisioned_id)
        .expect("provisioned host exists");
    provisioned.status = AgentHostStatus::Rejected;
    provisioned.enrollment_token_hash = None;
    provisioned.enrollment_token_expires_at = None;
    provisioned.updated_at = enrollment.now;
    Ok(AgentHostEnrollmentOutcome::Enrolled(Box::new(enrolled)))
}

pub(super) fn revoke(
    store: &MemoryAgentAuthStore,
    host_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<AgentHost>, AuthError> {
    let mut state = write(&store.state)?;
    let Some(host) = state.hosts.get_mut(host_id) else {
        return Ok(None);
    };
    host.status = AgentHostStatus::Revoked;
    host.public_key = None;
    host.kid = None;
    host.jwks_url = None;
    host.updated_at = now;
    let host = host.clone();
    let agent_ids = revoke_descendants(&mut state, host_id, now);
    revoke_grants(&mut state, &agent_ids, now);
    Ok(Some(host))
}

pub(super) fn switch_account(
    store: &MemoryAgentAuthStore,
    host_id: &str,
    user_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<AgentHostSwitchOutcome>, AuthError> {
    let mut state = write(&store.state)?;
    let Some(host) = state.hosts.get_mut(host_id) else {
        return Ok(None);
    };
    let previous_user_id = host.user_id.replace(user_id.to_owned());
    host.updated_at = now;
    let host = host.clone();
    let (revoked_agent_ids, claimed_agents) = switch_descendants(&mut state, host_id, user_id, now);
    let mut affected = revoked_agent_ids.clone();
    affected.extend(
        claimed_agents
            .iter()
            .map(|claimed| claimed.agent.id.clone()),
    );
    revoke_grants(&mut state, &affected, now);
    Ok(Some(AgentHostSwitchOutcome {
        host,
        previous_user_id,
        revoked_agent_ids,
        claimed_agents,
    }))
}

fn revoke_descendants(state: &mut State, host_id: &str, now: DateTime<Utc>) -> Vec<String> {
    let mut ids = Vec::new();
    for agent in state
        .agents
        .values_mut()
        .filter(|agent| agent.host_id == host_id)
    {
        agent.status = AgentStatus::Revoked;
        agent.public_key.clear();
        agent.kid = None;
        agent.jwks_url = None;
        agent.updated_at = now;
        ids.push(agent.id.clone());
    }
    ids
}

fn switch_descendants(
    state: &mut State,
    host_id: &str,
    user_id: &str,
    now: DateTime<Utc>,
) -> (Vec<String>, Vec<AgentClaimedAutonomousAgent>) {
    let mut revoked = Vec::new();
    let mut claimed = Vec::new();
    let mut agent_ids = state
        .agents
        .values()
        .filter(|agent| agent.host_id == host_id)
        .map(|agent| agent.id.clone())
        .collect::<Vec<_>>();
    agent_ids.sort();
    for agent_id in agent_ids {
        let capabilities = state
            .grants
            .values()
            .filter(|grant| grant.agent_id == agent_id && grant.status == AgentGrantStatus::Active)
            .map(|grant| grant.capability.clone())
            .collect::<Vec<_>>();
        let agent = state.agents.get_mut(&agent_id).expect("agent exists");
        if agent.mode == AgentMode::Autonomous && agent.status == AgentStatus::Active {
            agent.status = AgentStatus::Claimed;
            agent.user_id = Some(user_id.to_owned());
            agent.updated_at = now;
            claimed.push(AgentClaimedAutonomousAgent {
                agent: agent.clone(),
                capabilities,
            });
        } else if !matches!(
            agent.status,
            AgentStatus::Revoked | AgentStatus::Rejected | AgentStatus::Claimed
        ) {
            agent.status = AgentStatus::Revoked;
            agent.public_key.clear();
            agent.kid = None;
            agent.jwks_url = None;
            agent.updated_at = now;
            revoked.push(agent.id.clone());
        }
    }
    (revoked, claimed)
}

fn revoke_grants(state: &mut State, agent_ids: &[String], now: DateTime<Utc>) {
    for grant in state
        .grants
        .values_mut()
        .filter(|grant| agent_ids.contains(&grant.agent_id))
    {
        grant.status = AgentGrantStatus::Revoked;
        grant.updated_at = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_auth::{
        AgentAuthStore, AgentCapabilityGrant, AgentGrantStatus, AgentIdentity, AgentStatus,
    };

    fn host(id: &str, user_id: Uuid, now: DateTime<Utc>) -> AgentHost {
        AgentHost {
            id: id.into(),
            name: None,
            user_id: Some(user_id.to_string()),
            default_capabilities: vec![],
            public_key: Some(format!("key-{id}")),
            kid: None,
            jwks_url: None,
            enrollment_token_hash: None,
            enrollment_token_expires_at: None,
            status: AgentHostStatus::Active,
            activated_at: Some(now),
            expires_at: None,
            last_used_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn agent(id: &str, host_id: &str, mode: AgentMode, now: DateTime<Utc>) -> AgentIdentity {
        AgentIdentity {
            id: id.into(),
            name: id.into(),
            user_id: None,
            host_id: host_id.into(),
            status: AgentStatus::Active,
            mode,
            public_key: format!("key-{id}"),
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

    #[tokio::test]
    async fn switch_claims_autonomous_revokes_delegated_and_all_grants_atomically() {
        let store = MemoryAgentAuthStore::default();
        let now = Utc::now();
        let old_user = Uuid::new_v4();
        let new_user = Uuid::new_v4();
        store
            .create_host(host("host", old_user, now))
            .await
            .unwrap();
        for value in [
            agent("auto", "host", AgentMode::Autonomous, now),
            agent("delegated", "host", AgentMode::Delegated, now),
        ] {
            store.create_agent(value).await.unwrap();
        }
        for agent_id in ["auto", "delegated"] {
            store
                .create_grant(AgentCapabilityGrant {
                    id: format!("grant-{agent_id}"),
                    agent_id: agent_id.into(),
                    capability: "read".into(),
                    constraints: None,
                    denied_by: None,
                    granted_by: None,
                    expires_at: None,
                    status: AgentGrantStatus::Active,
                    reason: None,
                    created_at: now,
                    updated_at: now,
                })
                .await
                .unwrap();
        }
        let outcome = store
            .switch_host_account_cascade("host", &new_user.to_string(), now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            outcome
                .claimed_agents
                .iter()
                .map(|claimed| claimed.agent.id.as_str())
                .collect::<Vec<_>>(),
            ["auto"]
        );
        assert_eq!(outcome.claimed_agents[0].capabilities, ["read"]);
        assert_eq!(outcome.revoked_agent_ids, ["delegated"]);
        assert_eq!(
            store.find_agent("auto").await.unwrap().unwrap().status,
            AgentStatus::Claimed
        );
        assert_eq!(
            store.find_agent("delegated").await.unwrap().unwrap().status,
            AgentStatus::Revoked
        );
        for id in ["auto", "delegated"] {
            assert_eq!(
                store.find_grant(id, "read").await.unwrap().unwrap().status,
                AgentGrantStatus::Revoked
            );
        }
    }
}
