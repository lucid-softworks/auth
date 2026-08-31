mod agent;
mod agent_lifecycle;
mod approval;
mod grant;
mod host;
mod lifecycle;
mod rotation;
mod store;
mod transition;

use super::{AgentApprovalRequest, AgentCapabilityGrant, AgentHost, AgentIdentity};
use crate::AuthError;
use std::{
    collections::HashMap,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

#[derive(Debug, Default)]
pub struct MemoryAgentAuthStore {
    state: RwLock<State>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct AgentAuthSnapshot {
    pub(crate) hosts: HashMap<String, AgentHost>,
    pub(crate) agents: HashMap<String, AgentIdentity>,
    pub(crate) grants: HashMap<String, AgentCapabilityGrant>,
    pub(crate) approvals: HashMap<String, AgentApprovalRequest>,
}

type State = AgentAuthSnapshot;

impl MemoryAgentAuthStore {
    #[cfg(any(
        feature = "mysql",
        feature = "mssql",
        feature = "mongodb",
        feature = "sqlite"
    ))]
    pub(crate) fn from_snapshot(snapshot: AgentAuthSnapshot) -> Self {
        Self {
            state: RwLock::new(snapshot),
        }
    }

    #[cfg(any(
        feature = "mysql",
        feature = "mssql",
        feature = "mongodb",
        feature = "sqlite"
    ))]
    pub(crate) fn snapshot(&self) -> Result<AgentAuthSnapshot, AuthError> {
        Ok(read(&self.state)?.clone())
    }
}

pub(super) fn read(state: &RwLock<State>) -> Result<RwLockReadGuard<'_, State>, AuthError> {
    state
        .read()
        .map_err(|_| AuthError::Storage("agent-auth memory store lock poisoned".into()))
}

pub(super) fn write(state: &RwLock<State>) -> Result<RwLockWriteGuard<'_, State>, AuthError> {
    state
        .write()
        .map_err(|_| AuthError::Storage("agent-auth memory store lock poisoned".into()))
}
