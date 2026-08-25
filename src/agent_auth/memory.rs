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

#[derive(Debug, Default)]
pub(super) struct State {
    pub(super) hosts: HashMap<String, AgentHost>,
    pub(super) agents: HashMap<String, AgentIdentity>,
    pub(super) grants: HashMap<String, AgentCapabilityGrant>,
    pub(super) approvals: HashMap<String, AgentApprovalRequest>,
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
