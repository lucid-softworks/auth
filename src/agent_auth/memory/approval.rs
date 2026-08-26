use super::{MemoryAgentAuthStore, read, write};
use crate::{
    AuthError,
    agent_auth::{AgentApprovalRequest, AgentApprovalStatus, AgentStoreCreateOutcome},
};

pub(super) fn create(
    store: &MemoryAgentAuthStore,
    approval: AgentApprovalRequest,
) -> Result<AgentStoreCreateOutcome<AgentApprovalRequest>, AuthError> {
    let mut state = write(&store.state)?;
    let conflict = state.approvals.contains_key(&approval.id)
        || approval.user_code_hash.as_ref().is_some_and(|hash| {
            state
                .approvals
                .values()
                .any(|existing| existing.user_code_hash.as_ref() == Some(hash))
        });
    if conflict {
        return Ok(AgentStoreCreateOutcome::UniqueConflict);
    }
    state
        .approvals
        .insert(approval.id.clone(), approval.clone());
    Ok(AgentStoreCreateOutcome::Created(approval))
}

pub(super) fn find(
    store: &MemoryAgentAuthStore,
    predicate: impl Fn(&AgentApprovalRequest) -> bool,
) -> Result<Option<AgentApprovalRequest>, AuthError> {
    Ok(read(&store.state)?
        .approvals
        .values()
        .find(|approval| predicate(approval))
        .cloned())
}

pub(super) fn list_pending(
    store: &MemoryAgentAuthStore,
    user_id: &str,
) -> Result<Vec<AgentApprovalRequest>, AuthError> {
    let mut approvals: Vec<_> = read(&store.state)?
        .approvals
        .values()
        .filter(|approval| {
            approval.user_id.as_deref() == Some(user_id)
                && approval.status == AgentApprovalStatus::Pending
        })
        .cloned()
        .collect();
    approvals.sort_by_key(|approval| (approval.created_at, approval.id.clone()));
    Ok(approvals)
}

pub(super) fn list_pending_for_agent(
    store: &MemoryAgentAuthStore,
    agent_id: &str,
) -> Result<Vec<AgentApprovalRequest>, AuthError> {
    let mut approvals: Vec<_> = read(&store.state)?
        .approvals
        .values()
        .filter(|approval| {
            approval.agent_id.as_deref() == Some(agent_id)
                && approval.status == AgentApprovalStatus::Pending
        })
        .cloned()
        .collect();
    approvals.sort_by_key(|approval| (approval.created_at, approval.id.clone()));
    Ok(approvals)
}

pub(super) fn update(
    store: &MemoryAgentAuthStore,
    approval: AgentApprovalRequest,
) -> Result<Option<AgentApprovalRequest>, AuthError> {
    let mut state = write(&store.state)?;
    let Some(value) = state.approvals.get_mut(&approval.id) else {
        return Ok(None);
    };
    *value = approval.clone();
    Ok(Some(approval))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_auth::AgentApprovalMethod;
    use chrono::{Duration, Utc};

    fn approval(
        id: &str,
        agent_id: Option<&str>,
        status: AgentApprovalStatus,
    ) -> AgentApprovalRequest {
        let now = Utc::now();
        AgentApprovalRequest {
            id: id.into(),
            method: AgentApprovalMethod::DeviceAuthorization,
            agent_id: agent_id.map(str::to_owned),
            host_id: Some("host-1".into()),
            user_id: None,
            capabilities: None,
            status,
            user_code_hash: None,
            login_hint: None,
            binding_message: None,
            client_notification_token: None,
            client_notification_endpoint: None,
            delivery_mode: None,
            interval: 5.0,
            last_polled_at: None,
            expires_at: now + Duration::minutes(5),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn pending_agent_lookup_includes_requests_without_a_user() {
        let store = MemoryAgentAuthStore::default();
        create(
            &store,
            approval("one", Some("agent-1"), AgentApprovalStatus::Pending),
        )
        .unwrap();
        create(
            &store,
            approval("two", Some("agent-1"), AgentApprovalStatus::Approved),
        )
        .unwrap();
        create(
            &store,
            approval("three", Some("agent-2"), AgentApprovalStatus::Pending),
        )
        .unwrap();
        let found = list_pending_for_agent(&store, "agent-1").unwrap();
        assert_eq!(
            found
                .iter()
                .map(|value| value.id.as_str())
                .collect::<Vec<_>>(),
            ["one"]
        );
    }
}
