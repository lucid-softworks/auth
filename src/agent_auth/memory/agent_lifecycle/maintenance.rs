use super::super::{MemoryAgentAuthStore, write};
use crate::{
    AuthError,
    agent_auth::{AgentApprovalStatus, AgentCleanupOutcome, AgentKeyRotationOutcome, AgentStatus},
};
use chrono::{DateTime, Utc};

pub(in crate::agent_auth::memory) fn cleanup(
    store: &MemoryAgentAuthStore,
    user_id: &str,
    now: DateTime<Utc>,
) -> Result<AgentCleanupOutcome, AuthError> {
    let mut state = write(&store.state)?;
    let mut agent_ids = Vec::new();
    for agent in state.agents.values_mut().filter(|agent| {
        agent.user_id.as_deref() == Some(user_id)
            && agent.status == AgentStatus::Active
            && agent.expires_at.is_some_and(|expires_at| expires_at <= now)
    }) {
        agent.status = AgentStatus::Expired;
        agent.updated_at = now;
        agent_ids.push(agent.id.clone());
    }
    let mut approval_ids = Vec::new();
    for approval in state.approvals.values_mut().filter(|approval| {
        approval.user_id.as_deref() == Some(user_id)
            && approval.status == AgentApprovalStatus::Pending
            && approval.expires_at <= now
    }) {
        approval.status = AgentApprovalStatus::Expired;
        approval.updated_at = now;
        approval_ids.push(approval.id.clone());
    }
    Ok(AgentCleanupOutcome {
        agent_ids,
        approval_ids,
    })
}

pub(in crate::agent_auth::memory) fn rotate_key(
    store: &MemoryAgentAuthStore,
    agent_id: &str,
    public_key: String,
    kid: Option<String>,
    now: DateTime<Utc>,
) -> Result<AgentKeyRotationOutcome, AuthError> {
    let mut state = write(&store.state)?;
    let conflict = state.agents.values().any(|agent| {
        agent.id != agent_id
            && (agent.public_key == public_key
                || kid
                    .as_ref()
                    .is_some_and(|kid| agent.kid.as_ref() == Some(kid)))
    });
    if conflict {
        return Ok(AgentKeyRotationOutcome::UniqueConflict);
    }
    let Some(agent) = state.agents.get_mut(agent_id) else {
        return Ok(AgentKeyRotationOutcome::NotFound);
    };
    agent.public_key = public_key;
    agent.kid = kid;
    agent.updated_at = now;
    Ok(AgentKeyRotationOutcome::Rotated(Box::new(agent.clone())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_auth::memory::agent_lifecycle::fixtures::*;
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    #[test]
    fn cleanup_and_rotation_apply_only_to_eligible_records() {
        let store = MemoryAgentAuthStore::default();
        let now = Utc::now();
        let user_id = Uuid::new_v4();
        let mut expired = agent("expired", "host", user_id, now);
        expired.expires_at = Some(now - Duration::seconds(1));
        let other = agent("other", "host", user_id, now);
        {
            let mut state = write(&store.state).unwrap();
            state.agents.insert(expired.id.clone(), expired);
            state.agents.insert(other.id.clone(), other.clone());
            let mut pending = approval("approval", "expired", user_id, now);
            pending.expires_at = now - Duration::seconds(1);
            state.approvals.insert(pending.id.clone(), pending);
        }
        let cleaned = cleanup(&store, &user_id.to_string(), now).unwrap();
        assert_eq!(cleaned.agent_ids, ["expired"]);
        assert_eq!(cleaned.approval_ids, ["approval"]);
        assert_eq!(
            rotate_key(
                &store,
                "expired",
                other.public_key,
                Some("fresh-kid".into()),
                now,
            )
            .unwrap(),
            AgentKeyRotationOutcome::UniqueConflict
        );
    }
}
