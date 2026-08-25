use super::super::{MemoryAgentAuthStore, write};
use crate::{
    AuthError,
    agent_auth::{AgentGrantStatus, AgentRevocationOutcome, AgentStatus},
};
use chrono::{DateTime, Utc};

pub(in crate::agent_auth::memory) fn revoke(
    store: &MemoryAgentAuthStore,
    agent_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<AgentRevocationOutcome>, AuthError> {
    let mut state = write(&store.state)?;
    let Some(agent) = state.agents.get_mut(agent_id) else {
        return Ok(None);
    };
    agent.status = AgentStatus::Revoked;
    agent.public_key.clear();
    agent.kid = None;
    agent.updated_at = now;
    let agent = agent.clone();
    let mut grants_revoked = 0;
    for grant in state
        .grants
        .values_mut()
        .filter(|grant| grant.agent_id == agent_id)
    {
        grant.status = AgentGrantStatus::Revoked;
        grant.updated_at = now;
        grants_revoked += 1;
    }
    Ok(Some(AgentRevocationOutcome {
        agent,
        grants_revoked,
    }))
}

pub(in crate::agent_auth::memory) fn reactivate(
    store: &MemoryAgentAuthStore,
    agent: crate::AgentIdentity,
    grants: Vec<crate::AgentCapabilityGrant>,
) -> Result<Option<crate::AgentIdentity>, AuthError> {
    let mut state = write(&store.state)?;
    if !state.agents.contains_key(&agent.id) {
        return Ok(None);
    }
    state.grants.retain(|_, grant| grant.agent_id != agent.id);
    for grant in grants {
        state.grants.insert(grant.id.clone(), grant);
    }
    state.agents.insert(agent.id.clone(), agent.clone());
    Ok(Some(agent))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_auth::memory::{agent_lifecycle::fixtures::*, read};
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    #[test]
    fn revoke_clears_key_and_revokes_all_grants() {
        let store = MemoryAgentAuthStore::default();
        let now = Utc::now();
        let user_id = Uuid::new_v4();
        {
            let mut state = write(&store.state).unwrap();
            state
                .agents
                .insert("agent".into(), agent("agent", "host", user_id, now));
            state
                .grants
                .insert("one".into(), grant("one", "agent", "files.read", now));
            state
                .grants
                .insert("two".into(), grant("two", "agent", "files.write", now));
        }
        let outcome = revoke(&store, "agent", now + Duration::seconds(1))
            .unwrap()
            .unwrap();
        assert_eq!(outcome.grants_revoked, 2);
        assert_eq!(outcome.agent.status, AgentStatus::Revoked);
        assert!(outcome.agent.public_key.is_empty());
        assert!(outcome.agent.kid.is_none());
        assert!(
            read(&store.state)
                .unwrap()
                .grants
                .values()
                .all(|grant| grant.status == AgentGrantStatus::Revoked)
        );
    }

    #[test]
    fn reactivation_replaces_grants() {
        let store = MemoryAgentAuthStore::default();
        let now = Utc::now();
        let user_id = Uuid::new_v4();
        let mut reactivated = agent("agent", "host", user_id, now);
        reactivated.status = AgentStatus::Expired;
        {
            let mut state = write(&store.state).unwrap();
            state.agents.insert("agent".into(), reactivated.clone());
            state
                .grants
                .insert("old".into(), grant("old", "agent", "files.old", now));
        }
        reactivated.status = AgentStatus::Active;
        reactivate(
            &store,
            reactivated,
            vec![grant("new", "agent", "files.read", now)],
        )
        .unwrap();
        let state = read(&store.state).unwrap();
        assert!(!state.grants.contains_key("old"));
        assert!(state.grants.contains_key("new"));
    }
}
