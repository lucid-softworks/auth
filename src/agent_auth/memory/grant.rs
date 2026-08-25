use super::{MemoryAgentAuthStore, read, write};
use crate::{
    AuthError,
    agent_auth::{AgentCapabilityGrant, AgentStoreCreateOutcome},
};

pub(super) fn create(
    store: &MemoryAgentAuthStore,
    grant: AgentCapabilityGrant,
) -> Result<AgentStoreCreateOutcome<AgentCapabilityGrant>, AuthError> {
    let mut state = write(&store.state)?;
    if state.grants.contains_key(&grant.id) {
        return Ok(AgentStoreCreateOutcome::UniqueConflict);
    }
    state.grants.insert(grant.id.clone(), grant.clone());
    Ok(AgentStoreCreateOutcome::Created(grant))
}

pub(super) fn find(
    store: &MemoryAgentAuthStore,
    agent_id: &str,
    capability: &str,
) -> Result<Option<AgentCapabilityGrant>, AuthError> {
    Ok(read(&store.state)?
        .grants
        .values()
        .find(|grant| grant.agent_id == agent_id && grant.capability == capability)
        .cloned())
}

pub(super) fn find_by_id(
    store: &MemoryAgentAuthStore,
    id: &str,
) -> Result<Option<AgentCapabilityGrant>, AuthError> {
    Ok(read(&store.state)?.grants.get(id).cloned())
}

pub(super) fn list(
    store: &MemoryAgentAuthStore,
    agent_id: &str,
) -> Result<Vec<AgentCapabilityGrant>, AuthError> {
    let mut grants: Vec<_> = read(&store.state)?
        .grants
        .values()
        .filter(|grant| grant.agent_id == agent_id)
        .cloned()
        .collect();
    grants.sort_by_key(|grant| (grant.created_at, grant.id.clone()));
    Ok(grants)
}

pub(super) fn update(
    store: &MemoryAgentAuthStore,
    grant: AgentCapabilityGrant,
) -> Result<Option<AgentCapabilityGrant>, AuthError> {
    let mut state = write(&store.state)?;
    let Some(value) = state.grants.get_mut(&grant.id) else {
        return Ok(None);
    };
    *value = grant.clone();
    Ok(Some(grant))
}

pub(super) fn delete(store: &MemoryAgentAuthStore, id: &str) -> Result<bool, AuthError> {
    Ok(write(&store.state)?.grants.remove(id).is_some())
}

pub(super) fn consume(
    store: &MemoryAgentAuthStore,
    id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<bool, AuthError> {
    let mut state = write(&store.state)?;
    let Some(grant) = state.grants.get_mut(id) else {
        return Ok(false);
    };
    grant.status = crate::AgentGrantStatus::Consumed;
    grant.updated_at = now;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_auth::AgentGrantStatus;
    use chrono::Utc;

    fn grant(id: &str) -> AgentCapabilityGrant {
        let now = Utc::now();
        AgentCapabilityGrant {
            id: id.into(),
            agent_id: "agent-1".into(),
            capability: "mail.send".into(),
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
    fn preserves_multiple_historical_grants_for_one_capability() {
        let store = MemoryAgentAuthStore::default();
        assert!(matches!(
            create(&store, grant("grant-1")).unwrap(),
            AgentStoreCreateOutcome::Created(_)
        ));
        assert!(matches!(
            create(&store, grant("grant-2")).unwrap(),
            AgentStoreCreateOutcome::Created(_)
        ));
        assert_eq!(list(&store, "agent-1").unwrap().len(), 2);
        let consumed_at = Utc::now();
        assert!(consume(&store, "grant-2", consumed_at).unwrap());
        assert_eq!(
            find_by_id(&store, "grant-2").unwrap().unwrap().status,
            AgentGrantStatus::Consumed
        );
        assert!(!consume(&store, "missing", consumed_at).unwrap());
        assert!(delete(&store, "grant-1").unwrap());
        assert!(!delete(&store, "grant-1").unwrap());
    }
}
