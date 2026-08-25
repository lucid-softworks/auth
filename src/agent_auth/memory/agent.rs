use super::{MemoryAgentAuthStore, read, write};
use crate::{
    AuthError,
    agent_auth::{AgentIdentity, AgentStoreCreateOutcome},
};
pub(super) fn create(
    store: &MemoryAgentAuthStore,
    agent: AgentIdentity,
) -> Result<AgentStoreCreateOutcome<AgentIdentity>, AuthError> {
    let mut state = write(&store.state)?;
    let conflict = state.agents.contains_key(&agent.id)
        || agent.kid.as_ref().is_some_and(|kid| {
            state
                .agents
                .values()
                .any(|existing| existing.kid.as_ref() == Some(kid))
        })
        || state
            .agents
            .values()
            .any(|existing| existing.public_key == agent.public_key);
    if conflict {
        return Ok(AgentStoreCreateOutcome::UniqueConflict);
    }
    state.agents.insert(agent.id.clone(), agent.clone());
    Ok(AgentStoreCreateOutcome::Created(agent))
}

pub(super) fn find(
    store: &MemoryAgentAuthStore,
    predicate: impl Fn(&AgentIdentity) -> bool,
) -> Result<Option<AgentIdentity>, AuthError> {
    Ok(read(&store.state)?
        .agents
        .values()
        .find(|agent| predicate(agent))
        .cloned())
}

pub(super) fn list(
    store: &MemoryAgentAuthStore,
    predicate: impl Fn(&AgentIdentity) -> bool,
) -> Result<Vec<AgentIdentity>, AuthError> {
    let mut agents: Vec<_> = read(&store.state)?
        .agents
        .values()
        .filter(|agent| predicate(agent))
        .cloned()
        .collect();
    agents.sort_by_key(|agent| (agent.created_at, agent.id.clone()));
    Ok(agents)
}

pub(super) fn update(
    store: &MemoryAgentAuthStore,
    agent: AgentIdentity,
) -> Result<Option<AgentIdentity>, AuthError> {
    let mut state = write(&store.state)?;
    let Some(value) = state.agents.get_mut(&agent.id) else {
        return Ok(None);
    };
    *value = agent.clone();
    Ok(Some(agent))
}
