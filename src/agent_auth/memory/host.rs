use super::{MemoryAgentAuthStore, read, write};
use crate::{
    AuthError,
    agent_auth::{AgentHost, AgentStoreCreateOutcome},
};
use uuid::Uuid;

pub(super) fn create(
    store: &MemoryAgentAuthStore,
    host: AgentHost,
) -> Result<AgentStoreCreateOutcome<AgentHost>, AuthError> {
    let mut state = write(&store.state)?;
    let conflict = state.hosts.contains_key(&host.id)
        || host.kid.as_ref().is_some_and(|kid| {
            state
                .hosts
                .values()
                .any(|existing| existing.kid.as_ref() == Some(kid))
        })
        || host.enrollment_token_hash.as_ref().is_some_and(|hash| {
            state
                .hosts
                .values()
                .any(|existing| existing.enrollment_token_hash.as_ref() == Some(hash))
        });
    if conflict {
        return Ok(AgentStoreCreateOutcome::UniqueConflict);
    }
    state.hosts.insert(host.id.clone(), host.clone());
    Ok(AgentStoreCreateOutcome::Created(host))
}

pub(super) fn find(
    store: &MemoryAgentAuthStore,
    predicate: impl Fn(&AgentHost) -> bool,
) -> Result<Option<AgentHost>, AuthError> {
    Ok(read(&store.state)?
        .hosts
        .values()
        .find(|host| predicate(host))
        .cloned())
}

pub(super) fn list_for_user(
    store: &MemoryAgentAuthStore,
    user_id: Uuid,
) -> Result<Vec<AgentHost>, AuthError> {
    let mut hosts: Vec<_> = read(&store.state)?
        .hosts
        .values()
        .filter(|host| host.user_id == Some(user_id))
        .cloned()
        .collect();
    hosts.sort_by_key(|host| (host.created_at, host.id.clone()));
    Ok(hosts)
}

pub(super) fn update(
    store: &MemoryAgentAuthStore,
    host: AgentHost,
) -> Result<Option<AgentHost>, AuthError> {
    let mut state = write(&store.state)?;
    let Some(value) = state.hosts.get_mut(&host.id) else {
        return Ok(None);
    };
    *value = host.clone();
    Ok(Some(host))
}
