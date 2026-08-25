use super::{MemoryAgentAuthStore, write};
use crate::{
    AuthError,
    agent_auth::{
        AgentApprovalStatus, AgentCapabilityTransitionOutcome, AgentCapabilityTransitionPlan,
        AgentCapabilityTransitionResult,
    },
};

pub(super) fn apply(
    store: &MemoryAgentAuthStore,
    plan: AgentCapabilityTransitionPlan,
) -> Result<AgentCapabilityTransitionOutcome, AuthError> {
    let mut state = write(&store.state)?;
    if !state.agents.contains_key(&plan.expected_agent.id) {
        return Ok(AgentCapabilityTransitionOutcome::AgentNotFound);
    }
    if snapshot(&state, &plan) != expected_snapshot(&plan) || conflicts(&state, &plan) {
        return Ok(AgentCapabilityTransitionOutcome::Conflict);
    }
    apply_mutations(&mut state, &plan);
    Ok(AgentCapabilityTransitionOutcome::Applied(Box::new(result(
        &state,
        &plan.expected_agent.id,
    ))))
}

#[derive(PartialEq)]
struct Snapshot {
    agent: crate::AgentIdentity,
    host: Option<crate::AgentHost>,
    grants: Vec<crate::AgentCapabilityGrant>,
    approvals: Vec<crate::AgentApprovalRequest>,
    related_agents: Option<Vec<crate::AgentIdentity>>,
    related_grants: Option<Vec<crate::AgentCapabilityGrant>>,
}

fn snapshot(state: &super::State, plan: &AgentCapabilityTransitionPlan) -> Snapshot {
    let agent = state.agents[&plan.expected_agent.id].clone();
    let host = state.hosts.get(&plan.expected_agent.host_id).cloned();
    let mut current_grants = state
        .grants
        .values()
        .filter(|grant| grant.agent_id == plan.expected_agent.id)
        .cloned()
        .collect::<Vec<_>>();
    let mut current_approvals = state
        .approvals
        .values()
        .filter(|approval| {
            approval.agent_id.as_deref() == Some(&plan.expected_agent.id)
                && approval.status == AgentApprovalStatus::Pending
        })
        .cloned()
        .collect::<Vec<_>>();
    sort_records(&mut current_grants, &mut current_approvals);
    let (related_agents, related_grants) = if plan.expected_related_agents.is_some() {
        let mut agents = state
            .agents
            .values()
            .filter(|item| {
                item.host_id == plan.expected_agent.host_id && item.id != plan.expected_agent.id
            })
            .cloned()
            .collect::<Vec<_>>();
        agents.sort_by(|left, right| left.id.cmp(&right.id));
        let ids = agents
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>();
        let mut grants = state
            .grants
            .values()
            .filter(|grant| ids.contains(&grant.agent_id.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        grants.sort_by(|left, right| left.id.cmp(&right.id));
        (Some(agents), Some(grants))
    } else {
        (None, None)
    };
    Snapshot {
        agent,
        host,
        grants: current_grants,
        approvals: current_approvals,
        related_agents,
        related_grants,
    }
}

fn expected_snapshot(plan: &AgentCapabilityTransitionPlan) -> Snapshot {
    let mut expected_grants = plan.expected_grants.clone();
    let mut expected_approvals = plan.expected_approvals.clone();
    sort_records(&mut expected_grants, &mut expected_approvals);
    let mut related_agents = plan.expected_related_agents.clone();
    let mut related_grants = plan.expected_related_grants.clone();
    if let Some(values) = &mut related_agents {
        values.sort_by(|left, right| left.id.cmp(&right.id));
    }
    if let Some(values) = &mut related_grants {
        values.sort_by(|left, right| left.id.cmp(&right.id));
    }
    Snapshot {
        agent: plan.expected_agent.clone(),
        host: plan.expected_host.clone(),
        grants: expected_grants,
        approvals: expected_approvals,
        related_agents,
        related_grants,
    }
}

fn apply_mutations(state: &mut super::State, plan: &AgentCapabilityTransitionPlan) {
    if let Some(agent) = &plan.agent_update {
        state.agents.insert(agent.id.clone(), agent.clone());
    }
    for agent in &plan.related_agents_to_update {
        state.agents.insert(agent.id.clone(), agent.clone());
    }
    if let Some(host) = &plan.host_update {
        state.hosts.insert(host.id.clone(), host.clone());
    }
    for id in &plan.grant_ids_to_delete {
        state.grants.remove(id);
    }
    for grant in plan
        .grants_to_update
        .iter()
        .chain(&plan.related_grants_to_update)
        .chain(&plan.grants_to_create)
    {
        state.grants.insert(grant.id.clone(), grant.clone());
    }
    for approval in &plan.approvals_to_update {
        state
            .approvals
            .insert(approval.id.clone(), approval.clone());
    }
    if let Some(approval) = &plan.approval_to_create {
        state
            .approvals
            .insert(approval.id.clone(), approval.clone());
    }
}

fn result(state: &super::State, agent_id: &str) -> AgentCapabilityTransitionResult {
    let agent = state.agents[agent_id].clone();
    let host = state.hosts.get(&agent.host_id).cloned();
    let mut grants = state
        .grants
        .values()
        .filter(|grant| grant.agent_id == agent.id)
        .cloned()
        .collect::<Vec<_>>();
    let mut approvals = state
        .approvals
        .values()
        .filter(|approval| approval.agent_id.as_deref() == Some(&agent.id))
        .cloned()
        .collect::<Vec<_>>();
    sort_records(&mut grants, &mut approvals);
    AgentCapabilityTransitionResult {
        agent,
        host,
        grants,
        approvals,
    }
}

fn conflicts(state: &super::State, plan: &AgentCapabilityTransitionPlan) -> bool {
    plan.grants_to_create
        .iter()
        .any(|grant| state.grants.contains_key(&grant.id))
        || plan.approval_to_create.as_ref().is_some_and(|approval| {
            state.approvals.contains_key(&approval.id)
                || approval.user_code_hash.as_ref().is_some_and(|hash| {
                    state
                        .approvals
                        .values()
                        .any(|item| item.user_code_hash.as_ref() == Some(hash))
                })
        })
        || plan
            .grants_to_update
            .iter()
            .chain(&plan.related_grants_to_update)
            .any(|grant| !state.grants.contains_key(&grant.id))
        || plan
            .related_agents_to_update
            .iter()
            .any(|agent| !state.agents.contains_key(&agent.id))
        || plan
            .approvals_to_update
            .iter()
            .any(|approval| !state.approvals.contains_key(&approval.id))
}

fn sort_records(
    grants: &mut [crate::AgentCapabilityGrant],
    approvals: &mut [crate::AgentApprovalRequest],
) {
    grants.sort_by(|left, right| left.id.cmp(&right.id));
    approvals.sort_by(|left, right| left.id.cmp(&right.id));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AgentCapabilityGrant, AgentCapabilityTransitionPlan, AgentGrantStatus, AgentHost,
        AgentHostStatus, AgentIdentity, AgentMode, AgentStatus,
    };
    use chrono::Utc;

    fn fixtures() -> (MemoryAgentAuthStore, AgentIdentity, AgentHost) {
        let now = Utc::now();
        let host = AgentHost {
            id: "host".into(),
            name: None,
            user_id: None,
            default_capabilities: Vec::new(),
            public_key: None,
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
        };
        let agent = AgentIdentity {
            id: "agent".into(),
            name: "Agent".into(),
            user_id: None,
            host_id: host.id.clone(),
            status: AgentStatus::Active,
            mode: AgentMode::Autonomous,
            public_key: "{}".into(),
            kid: None,
            jwks_url: None,
            last_used_at: None,
            activated_at: Some(now),
            expires_at: None,
            metadata: None,
            created_at: now,
            updated_at: now,
        };
        let store = MemoryAgentAuthStore::default();
        {
            let mut state = write(&store.state).unwrap();
            state.hosts.insert(host.id.clone(), host.clone());
            state.agents.insert(agent.id.clone(), agent.clone());
        }
        (store, agent, host)
    }

    fn grant(id: &str) -> AgentCapabilityGrant {
        let now = Utc::now();
        AgentCapabilityGrant {
            id: id.into(),
            agent_id: "agent".into(),
            capability: "mail.send".into(),
            constraints: None,
            denied_by: None,
            granted_by: None,
            expires_at: None,
            status: AgentGrantStatus::Pending,
            reason: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn plan(
        agent: AgentIdentity,
        host: AgentHost,
        create: AgentCapabilityGrant,
    ) -> AgentCapabilityTransitionPlan {
        AgentCapabilityTransitionPlan {
            expected_agent: agent,
            expected_host: Some(host),
            expected_grants: Vec::new(),
            expected_approvals: Vec::new(),
            expected_related_agents: None,
            expected_related_grants: None,
            agent_update: None,
            host_update: None,
            related_agents_to_update: Vec::new(),
            related_grants_to_update: Vec::new(),
            grants_to_create: vec![create],
            grants_to_update: Vec::new(),
            grant_ids_to_delete: Vec::new(),
            approval_to_create: None,
            approvals_to_update: Vec::new(),
        }
    }

    #[test]
    fn applies_once_and_rejects_a_stale_snapshot_without_partial_writes() {
        let (store, agent, host) = fixtures();
        let first = apply(&store, plan(agent.clone(), host.clone(), grant("one"))).unwrap();
        assert!(matches!(
            first,
            AgentCapabilityTransitionOutcome::Applied(_)
        ));
        let stale = apply(&store, plan(agent, host, grant("two"))).unwrap();
        assert_eq!(stale, AgentCapabilityTransitionOutcome::Conflict);
        let state = super::super::read(&store.state).unwrap();
        assert!(state.grants.contains_key("one"));
        assert!(!state.grants.contains_key("two"));
    }
}
