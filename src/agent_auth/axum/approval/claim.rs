use super::{
    error::{FlowError, Result},
    support::{emit, format_grants},
};
use crate::{
    AgentApprovalStatus, AgentAuthAuditEventType, AgentAuthEventFields,
    AgentCapabilityTransitionOutcome, AgentCapabilityTransitionPlan, AgentGrantStatus,
    AgentResolveApprovalTransition, AgentStatus, agent_auth::axum::AgentAuthState,
};
use chrono::Utc;
use serde_json::{Map, Value, json};

pub(super) struct ClaimRequest<'a> {
    pub(super) agent: &'a mut crate::AgentIdentity,
    pub(super) grants: Vec<crate::AgentCapabilityGrant>,
    pub(super) host: Option<crate::AgentHost>,
    pub(super) approvals: Vec<crate::AgentApprovalRequest>,
    pub(super) approve: bool,
    pub(super) reason: Option<String>,
}

pub(super) async fn run(
    state: &AgentAuthState,
    session: &crate::SessionWithUser,
    request: ClaimRequest<'_>,
) -> Result<Value> {
    let ClaimRequest {
        agent,
        grants,
        host,
        approvals,
        approve,
        reason,
    } = request;
    let now = Utc::now();
    let expected_agent = agent.clone();
    if !approve {
        return deny(
            state,
            session,
            agent,
            expected_agent,
            host,
            grants,
            approvals,
            reason,
        )
        .await;
    }
    agent.status = AgentStatus::Claimed;
    agent.user_id = Some(session.user.id.clone());
    agent.updated_at = now;
    let mut host_update = None;
    if let Some(mut host) = host.clone()
        && host.user_id.is_none()
    {
        host.user_id = Some(session.user.id.clone());
        host.updated_at = now;
        host_update = Some(host.clone());
    }
    let active = grants
        .iter()
        .filter(|grant| grant.status == AgentGrantStatus::Active)
        .map(|grant| grant.capability.clone())
        .collect::<Vec<_>>();
    let updates = approval_updates(&approvals, AgentApprovalStatus::Approved, now);
    apply(
        state,
        expected_agent,
        host.clone(),
        grants.clone(),
        approvals.clone(),
        Some(agent.clone()),
        host_update.clone(),
        updates,
    )
    .await?;
    after_claim(state, session, agent, host_update, host, &active).await;
    super::notifications::deliver(
        &approvals,
        json!({"agent_id": agent.id, "status": "approved"}),
    );
    emit(
        &state.config,
        AgentAuthAuditEventType::AgentClaimed,
        AgentAuthEventFields {
            actor_id: Some(session.user.id.to_string()),
            agent_id: Some(agent.id.clone()),
            host_id: Some(agent.host_id.clone()),
            metadata: Some(Map::from_iter([("capabilities".into(), json!(active))])),
            ..AgentAuthEventFields::default()
        },
    )
    .await;
    Ok(
        json!({"status": "approved", "agentId": agent.id, "claimed": true, "agent_capability_grants": format_grants(&grants, &state.config)}),
    )
}

#[allow(clippy::too_many_arguments)]
async fn deny(
    state: &AgentAuthState,
    session: &crate::SessionWithUser,
    agent: &crate::AgentIdentity,
    expected_agent: crate::AgentIdentity,
    host: Option<crate::AgentHost>,
    grants: Vec<crate::AgentCapabilityGrant>,
    approvals: Vec<crate::AgentApprovalRequest>,
    reason: Option<String>,
) -> Result<Value> {
    let updates = approval_updates(&approvals, AgentApprovalStatus::Denied, Utc::now());
    apply(
        state,
        expected_agent,
        host,
        grants,
        approvals.clone(),
        None,
        None,
        updates,
    )
    .await?;
    super::notifications::deliver(
        &approvals,
        json!({"agent_id": agent.id, "status": "denied", "error": "access_denied", "message": reason.clone().unwrap_or_else(|| "User denied the claim request.".into())}),
    );
    emit(
        &state.config,
        AgentAuthAuditEventType::CapabilityDenied,
        AgentAuthEventFields {
            actor_id: Some(session.user.id.to_string()),
            agent_id: Some(agent.id.clone()),
            metadata: Some(Map::from_iter([
                ("claim".into(), json!(true)),
                ("reason".into(), json!(reason)),
            ])),
            ..AgentAuthEventFields::default()
        },
    )
    .await;
    Ok(json!({"status": "denied", "agentId": agent.id}))
}

async fn after_claim(
    state: &AgentAuthState,
    session: &crate::SessionWithUser,
    agent: &crate::AgentIdentity,
    host_update: Option<crate::AgentHost>,
    host: Option<crate::AgentHost>,
    active: &[String],
) {
    if let Some(claimed_host) = &host_update
        && let Some(callback) = &state.config.on_host_claimed
    {
        callback
            .call(crate::AgentHostClaimedContext {
                endpoint: crate::AgentEndpointContext::default(),
                host_id: claimed_host.id.clone(),
                user_id: session.user.id.clone(),
                previous_user_id: None,
            })
            .await;
    }
    if let Some(callback) = &state.config.on_autonomous_agent_claimed
        && let Some(host) = host_update.or(host)
    {
        callback
            .call(crate::AgentAutonomousClaimedContext {
                endpoint: crate::AgentEndpointContext::default(),
                agent: agent.clone(),
                host,
                user_id: session.user.id.clone(),
                capabilities: active.to_vec(),
            })
            .await;
    }
}

fn approval_updates(
    values: &[crate::AgentApprovalRequest],
    status: AgentApprovalStatus,
    now: chrono::DateTime<Utc>,
) -> Vec<crate::AgentApprovalRequest> {
    values
        .iter()
        .cloned()
        .map(|mut value| {
            value.status = status;
            value.updated_at = now;
            value
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn apply(
    state: &AgentAuthState,
    expected_agent: crate::AgentIdentity,
    host: Option<crate::AgentHost>,
    grants: Vec<crate::AgentCapabilityGrant>,
    approvals: Vec<crate::AgentApprovalRequest>,
    agent_update: Option<crate::AgentIdentity>,
    host_update: Option<crate::AgentHost>,
    approvals_to_update: Vec<crate::AgentApprovalRequest>,
) -> Result<()> {
    let outcome = state
        .store
        .resolve_approval_atomic(AgentResolveApprovalTransition(
            AgentCapabilityTransitionPlan {
                expected_agent,
                expected_host: host,
                expected_grants: grants,
                expected_approvals: approvals,
                expected_related_agents: None,
                expected_related_grants: None,
                agent_update,
                host_update,
                related_agents_to_update: Vec::new(),
                related_grants_to_update: Vec::new(),
                grants_to_create: Vec::new(),
                grants_to_update: Vec::new(),
                grant_ids_to_delete: Vec::new(),
                approval_to_create: None,
                approvals_to_update,
            },
        ))
        .await?;
    if matches!(outcome, AgentCapabilityTransitionOutcome::Applied(_)) {
        Ok(())
    } else {
        Err(FlowError::internal())
    }
}
