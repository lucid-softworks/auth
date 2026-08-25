use super::error::{FlowError, Result};
use crate::{
    AgentApprovalMethod, AgentApprovalStatus, AgentCapabilityTransitionOutcome,
    AgentCapabilityTransitionPlan, AgentResolveApprovalTransition,
    agent_auth::axum::AgentAuthState,
};
use chrono::Utc;

pub(super) fn device_approvals(
    selected: Option<crate::AgentApprovalRequest>,
    pending: &[crate::AgentApprovalRequest],
) -> Vec<crate::AgentApprovalRequest> {
    if let Some(selected) = selected {
        return (selected.method == AgentApprovalMethod::DeviceAuthorization)
            .then_some(selected)
            .into_iter()
            .collect();
    }
    pending
        .iter()
        .filter(|approval| approval.method == AgentApprovalMethod::DeviceAuthorization)
        .cloned()
        .collect()
}

pub(super) fn resolved_approvals(
    values: &[crate::AgentApprovalRequest],
    status: AgentApprovalStatus,
    now: chrono::DateTime<Utc>,
) -> Vec<crate::AgentApprovalRequest> {
    values
        .iter()
        .cloned()
        .map(|mut approval| {
            approval.status = status;
            approval.updated_at = now;
            approval
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_resolution(
    state: &AgentAuthState,
    expected_agent: &crate::AgentIdentity,
    host: Option<crate::AgentHost>,
    expected_grants: Vec<crate::AgentCapabilityGrant>,
    expected_approvals: Vec<crate::AgentApprovalRequest>,
    agent_update: Option<crate::AgentIdentity>,
    activation: Option<&super::activation::PendingActivation>,
    grants_to_update: Vec<crate::AgentCapabilityGrant>,
    grant_ids_to_delete: Vec<String>,
    approvals_to_update: Vec<crate::AgentApprovalRequest>,
) -> Result<()> {
    let outcome = state
        .store
        .resolve_approval_atomic(AgentResolveApprovalTransition(
            AgentCapabilityTransitionPlan {
                expected_agent: expected_agent.clone(),
                expected_host: host,
                expected_grants,
                expected_approvals,
                expected_related_agents: activation
                    .map(|activation| activation.expected_agents.clone()),
                expected_related_grants: activation
                    .map(|activation| activation.expected_grants.clone()),
                agent_update,
                host_update: activation.map(|activation| activation.host_update.clone()),
                related_agents_to_update: activation
                    .map(|activation| activation.agent_updates.clone())
                    .unwrap_or_default(),
                related_grants_to_update: activation
                    .map(|activation| activation.grant_updates.clone())
                    .unwrap_or_default(),
                grants_to_create: Vec::new(),
                grants_to_update,
                grant_ids_to_delete,
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
