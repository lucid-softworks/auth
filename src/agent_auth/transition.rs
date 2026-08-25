use super::{AgentApprovalRequest, AgentCapabilityGrant, AgentHost, AgentIdentity};

#[derive(Debug, Clone, PartialEq)]
pub struct AgentCapabilityTransitionPlan {
    pub expected_agent: AgentIdentity,
    pub expected_host: Option<AgentHost>,
    pub expected_grants: Vec<AgentCapabilityGrant>,
    pub expected_approvals: Vec<AgentApprovalRequest>,
    /// Full host-scoped snapshots used when activating a pending agent transfers a host.
    pub expected_related_agents: Option<Vec<AgentIdentity>>,
    pub expected_related_grants: Option<Vec<AgentCapabilityGrant>>,
    pub agent_update: Option<AgentIdentity>,
    pub host_update: Option<AgentHost>,
    pub related_agents_to_update: Vec<AgentIdentity>,
    pub related_grants_to_update: Vec<AgentCapabilityGrant>,
    pub grants_to_create: Vec<AgentCapabilityGrant>,
    pub grants_to_update: Vec<AgentCapabilityGrant>,
    pub grant_ids_to_delete: Vec<String>,
    pub approval_to_create: Option<AgentApprovalRequest>,
    pub approvals_to_update: Vec<AgentApprovalRequest>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentRequestCapabilitiesTransition(pub AgentCapabilityTransitionPlan);

#[derive(Debug, Clone, PartialEq)]
pub struct AgentResolveApprovalTransition(pub AgentCapabilityTransitionPlan);

#[derive(Debug, Clone, PartialEq)]
pub struct AgentGrantCapabilitiesTransition(pub AgentCapabilityTransitionPlan);

#[derive(Debug, Clone, PartialEq)]
pub struct AgentRevokeCapabilitiesTransition(pub AgentCapabilityTransitionPlan);

#[derive(Debug, Clone, PartialEq)]
pub struct AgentCapabilityTransitionResult {
    pub agent: AgentIdentity,
    pub host: Option<AgentHost>,
    pub grants: Vec<AgentCapabilityGrant>,
    pub approvals: Vec<AgentApprovalRequest>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentCapabilityTransitionOutcome {
    Applied(Box<AgentCapabilityTransitionResult>),
    Conflict,
    AgentNotFound,
}
