use super::super::{MemoryAgentAuthStore, State, write};
use crate::{
    AuthError,
    agent_auth::{AgentRegistrationBundle, AgentRegistrationOutcome},
};
use std::collections::HashSet;

pub(in crate::agent_auth::memory) fn register(
    store: &MemoryAgentAuthStore,
    bundle: AgentRegistrationBundle,
) -> Result<AgentRegistrationOutcome, AuthError> {
    let mut state = write(&store.state)?;
    if registration_conflicts(&state, &bundle) {
        return Ok(AgentRegistrationOutcome::UniqueConflict);
    }
    if let Some(host) = &bundle.host {
        state.hosts.insert(host.id.clone(), host.clone());
    }
    state
        .agents
        .insert(bundle.agent.id.clone(), bundle.agent.clone());
    for grant in &bundle.grants {
        state.grants.insert(grant.id.clone(), grant.clone());
    }
    if let Some(approval) = &bundle.approval {
        state
            .approvals
            .insert(approval.id.clone(), approval.clone());
    }
    Ok(AgentRegistrationOutcome::Registered(Box::new(bundle)))
}

fn registration_conflicts(state: &State, bundle: &AgentRegistrationBundle) -> bool {
    invalid_relationships(bundle)
        || host_conflict(state, bundle)
        || agent_conflict(state, bundle)
        || grant_conflict(state, bundle)
        || approval_conflict(state, bundle)
}

fn invalid_relationships(bundle: &AgentRegistrationBundle) -> bool {
    if bundle
        .host
        .as_ref()
        .is_some_and(|host| host.id != bundle.agent.host_id)
    {
        return true;
    }
    let mut ids = HashSet::new();
    let mut pairs = HashSet::new();
    bundle.grants.iter().any(|grant| {
        grant.agent_id != bundle.agent.id
            || !ids.insert(&grant.id)
            || !pairs.insert((&grant.agent_id, &grant.capability))
    })
}

fn host_conflict(state: &State, bundle: &AgentRegistrationBundle) -> bool {
    bundle.host.as_ref().is_some_and(|host| {
        state.hosts.contains_key(&host.id)
            || host.kid.as_ref().is_some_and(|kid| {
                state
                    .hosts
                    .values()
                    .any(|existing| existing.kid.as_ref() == Some(kid))
            })
            || host.public_key.as_ref().is_some_and(|key| {
                state
                    .hosts
                    .values()
                    .any(|existing| existing.public_key.as_ref() == Some(key))
            })
    })
}

fn agent_conflict(state: &State, bundle: &AgentRegistrationBundle) -> bool {
    state.agents.contains_key(&bundle.agent.id)
        || bundle.agent.kid.as_ref().is_some_and(|kid| {
            state
                .agents
                .values()
                .any(|existing| existing.kid.as_ref() == Some(kid))
        })
        || state
            .agents
            .values()
            .any(|existing| existing.public_key == bundle.agent.public_key)
}

fn grant_conflict(state: &State, bundle: &AgentRegistrationBundle) -> bool {
    bundle.grants.iter().any(|grant| {
        state.grants.contains_key(&grant.id)
            || state.grants.values().any(|existing| {
                existing.agent_id == grant.agent_id && existing.capability == grant.capability
            })
    })
}

fn approval_conflict(state: &State, bundle: &AgentRegistrationBundle) -> bool {
    bundle.approval.as_ref().is_some_and(|approval| {
        state.approvals.contains_key(&approval.id)
            || approval.user_code_hash.as_ref().is_some_and(|hash| {
                state
                    .approvals
                    .values()
                    .any(|existing| existing.user_code_hash.as_ref() == Some(hash))
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_auth::memory::{agent_lifecycle::fixtures::*, read};
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn bundle_is_all_or_nothing_on_conflict() {
        let store = MemoryAgentAuthStore::default();
        let now = Utc::now();
        let user_id = Uuid::new_v4();
        let existing = agent("existing", "host-old", user_id, now);
        write(&store.state)
            .unwrap()
            .agents
            .insert(existing.id.clone(), existing.clone());
        let mut incoming = agent("new", "host-new", user_id, now);
        incoming.public_key = existing.public_key;
        let bundle = AgentRegistrationBundle {
            host: Some(host("host-new", user_id, now)),
            grants: vec![grant("grant-new", "new", "files.read", now)],
            approval: Some(approval("approval-new", "new", user_id, now)),
            agent: incoming,
        };
        assert_eq!(
            register(&store, bundle).unwrap(),
            AgentRegistrationOutcome::UniqueConflict
        );
        let state = read(&store.state).unwrap();
        assert!(!state.hosts.contains_key("host-new"));
        assert!(!state.agents.contains_key("new"));
        assert!(!state.grants.contains_key("grant-new"));
        assert!(!state.approvals.contains_key("approval-new"));
    }

    #[test]
    fn bundle_persists_every_record_together() {
        let store = MemoryAgentAuthStore::default();
        let now = Utc::now();
        let user_id = Uuid::new_v4();
        let bundle = AgentRegistrationBundle {
            host: Some(host("host-new", user_id, now)),
            agent: agent("new", "host-new", user_id, now),
            grants: vec![grant("grant-new", "new", "files.read", now)],
            approval: Some(approval("approval-new", "new", user_id, now)),
        };
        assert!(matches!(
            register(&store, bundle).unwrap(),
            AgentRegistrationOutcome::Registered(_)
        ));
        let state = read(&store.state).unwrap();
        assert!(state.hosts.contains_key("host-new"));
        assert!(state.agents.contains_key("new"));
        assert!(state.grants.contains_key("grant-new"));
        assert!(state.approvals.contains_key("approval-new"));
    }
}
