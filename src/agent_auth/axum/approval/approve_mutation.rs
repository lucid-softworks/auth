use super::{
    approve_flow::Approval,
    error::Result,
    support::{emit, expires_at},
};
use crate::{
    AgentAuthAuditEventType, AgentAuthEventFields, AgentCapabilityGrant, AgentGrantStatus,
    AgentStatus,
    agent_auth::{axum::AgentAuthState, policy},
};
use chrono::Duration;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};

pub(super) struct Mutations {
    pub(super) added: Vec<String>,
    updates: Vec<AgentCapabilityGrant>,
    deletes: Vec<String>,
}

pub(super) async fn build_mutations(
    state: &AgentAuthState,
    session: &crate::SessionWithUser,
    approval: &Approval,
    approved: HashSet<String>,
    ttl: Option<f64>,
) -> Mutations {
    let mut active = active_by_capability(&approval.grants);
    let mut result = Mutations {
        added: Vec::new(),
        updates: Vec::new(),
        deletes: Vec::new(),
    };
    for mut grant in approval.pending.clone() {
        if approved.contains(&grant.capability) {
            let covered = active.get(&grant.capability).is_some_and(|items| {
                items.iter().any(|item| {
                    policy::constraints_cover(item.constraints.as_ref(), grant.constraints.as_ref())
                })
            });
            if covered {
                result.deletes.push(grant.id);
                continue;
            }
            grant.status = AgentGrantStatus::Active;
            grant.expires_at =
                expires_at(&state.config, &grant.capability, &approval.agent, ttl).await;
            grant.granted_by = Some(session.user.id.clone());
            active
                .entry(grant.capability.clone())
                .or_default()
                .push(grant.clone());
            result.added.push(grant.capability.clone());
        } else {
            grant.status = AgentGrantStatus::Denied;
        }
        grant.updated_at = approval.now;
        result.updates.push(grant);
    }
    result
}

fn active_by_capability(
    grants: &[AgentCapabilityGrant],
) -> HashMap<String, Vec<AgentCapabilityGrant>> {
    let mut active = HashMap::new();
    for grant in grants
        .iter()
        .filter(|grant| grant.status == AgentGrantStatus::Active)
    {
        active
            .entry(grant.capability.clone())
            .or_insert_with(Vec::new)
            .push(grant.clone());
    }
    active
}

pub(super) async fn activate(
    state: &AgentAuthState,
    session: &crate::SessionWithUser,
    approval: &mut Approval,
) -> Result<Option<super::activation::PendingActivation>> {
    if !approval.agent_pending {
        return Ok(None);
    }
    let activation = super::activation::prepare(
        state,
        approval.host.as_ref(),
        &approval.agent_id,
        &session.user.id,
        approval.now,
    )
    .await?;
    approval.agent.status = AgentStatus::Active;
    approval.agent.user_id = Some(session.user.id.clone());
    approval.agent.activated_at = Some(approval.now);
    approval.agent.expires_at = (state.config.agent_session_ttl > 0)
        .then(|| approval.now + Duration::seconds(state.config.agent_session_ttl as i64));
    approval.agent.updated_at = approval.now;
    Ok(activation)
}

pub(super) async fn apply_approval(
    state: &AgentAuthState,
    approval: Approval,
    mutations: Mutations,
    updates: Vec<crate::AgentApprovalRequest>,
    activation: Option<super::activation::PendingActivation>,
) -> Result<Value> {
    super::resolution::apply_resolution(
        state,
        &approval.expected_agent,
        approval.host,
        approval.grants,
        approval.approvals.clone(),
        approval.agent_pending.then_some(approval.agent),
        activation.as_ref(),
        mutations.updates,
        mutations.deletes,
        updates,
    )
    .await?;
    if let Some(activation) = &activation {
        super::activation::after_commit(state, activation, &approval.user_id).await;
    }
    super::notifications::deliver(
        &approval.approvals,
        json!({"agent_id": approval.agent_id, "status": "approved"}),
    );
    emit(
        &state.config,
        AgentAuthAuditEventType::CapabilityApproved,
        AgentAuthEventFields {
            actor_id: Some(approval.user_id.to_string()),
            agent_id: Some(approval.agent_id.clone()),
            metadata: Some(Map::from_iter([(
                "capabilities".into(),
                json!(mutations.added),
            )])),
            ..AgentAuthEventFields::default()
        },
    )
    .await;
    Ok(json!({
        "status": "approved", "agentId": approval.agent_id, "added": mutations.added
    }))
}
