use super::{MemoryAgentAuthStore, write};
use crate::{AuthError, agent_auth::AgentHostRotationOutcome};
use chrono::{DateTime, Utc};

pub(super) fn rotate_key(
    store: &MemoryAgentAuthStore,
    old_id: &str,
    new_id: &str,
    public_key: String,
    kid: Option<String>,
    now: DateTime<Utc>,
) -> Result<AgentHostRotationOutcome, AuthError> {
    let mut state = write(&store.state)?;
    if old_id != new_id && state.hosts.contains_key(new_id) {
        return Ok(AgentHostRotationOutcome::UniqueConflict);
    }
    let Some(mut host) = state.hosts.remove(old_id) else {
        return Ok(AgentHostRotationOutcome::NotFound);
    };
    host.id = new_id.to_owned();
    host.public_key = Some(public_key);
    host.kid = kid;
    host.jwks_url = None;
    host.updated_at = now;
    for agent in state
        .agents
        .values_mut()
        .filter(|agent| agent.host_id == old_id)
    {
        agent.host_id = new_id.to_owned();
        agent.updated_at = now;
    }
    for approval in state
        .approvals
        .values_mut()
        .filter(|approval| approval.host_id.as_deref() == Some(old_id))
    {
        approval.host_id = Some(new_id.to_owned());
        approval.updated_at = now;
    }
    state.hosts.insert(new_id.to_owned(), host.clone());
    Ok(AgentHostRotationOutcome::Rotated(Box::new(host)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_auth::{
        AgentApprovalMethod, AgentApprovalRequest, AgentApprovalStatus, AgentAuthStore, AgentHost,
        AgentHostStatus, AgentIdentity, AgentMode, AgentStatus,
    };
    use uuid::Uuid;

    #[tokio::test]
    async fn rewrites_agent_and_pending_approval_host_references() {
        let store = MemoryAgentAuthStore::default();
        let now = Utc::now();
        store.create_host(host("old", now)).await.unwrap();
        store.create_agent(agent("old", now)).await.unwrap();
        store.create_approval(approval("old", now)).await.unwrap();

        store
            .rotate_host_key("old", "new", "new-key".into(), None, now)
            .await
            .unwrap();

        assert_eq!(
            store.find_agent("agent").await.unwrap().unwrap().host_id,
            "new"
        );
        assert_eq!(
            store
                .find_approval("approval")
                .await
                .unwrap()
                .unwrap()
                .host_id
                .as_deref(),
            Some("new")
        );
    }

    fn host(id: &str, now: DateTime<Utc>) -> AgentHost {
        AgentHost {
            id: id.into(),
            name: None,
            user_id: Some(Uuid::new_v4()),
            default_capabilities: vec![],
            public_key: Some("old-key".into()),
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

    fn agent(host_id: &str, now: DateTime<Utc>) -> AgentIdentity {
        AgentIdentity {
            id: "agent".into(),
            name: "agent".into(),
            user_id: None,
            host_id: host_id.into(),
            status: AgentStatus::Active,
            mode: AgentMode::Delegated,
            public_key: "agent-key".into(),
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

    fn approval(host_id: &str, now: DateTime<Utc>) -> AgentApprovalRequest {
        AgentApprovalRequest {
            id: "approval".into(),
            method: AgentApprovalMethod::Ciba,
            agent_id: Some("agent".into()),
            host_id: Some(host_id.into()),
            user_id: None,
            capabilities: None,
            status: AgentApprovalStatus::Pending,
            user_code_hash: None,
            login_hint: None,
            binding_message: None,
            client_notification_token: None,
            client_notification_endpoint: None,
            delivery_mode: None,
            interval: 5.0,
            last_polled_at: None,
            expires_at: now,
            created_at: now,
            updated_at: now,
        }
    }
}
