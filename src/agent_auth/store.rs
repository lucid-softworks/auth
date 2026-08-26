use super::{
    AgentApprovalRequest, AgentCapabilityGrant, AgentCapabilityTransitionOutcome,
    AgentGrantCapabilitiesTransition, AgentHost, AgentIdentity, AgentRequestCapabilitiesTransition,
    AgentResolveApprovalTransition, AgentRevokeCapabilitiesTransition,
};
use crate::AuthError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq)]
pub enum AgentStoreCreateOutcome<T> {
    Created(T),
    UniqueConflict,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentHostEnrollment {
    pub public_key: String,
    pub kid: Option<String>,
    pub name: Option<String>,
    pub now: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentHostEnrollmentOutcome {
    Enrolled(Box<AgentHost>),
    TokenNotFound,
    TokenExpired,
    HostNotPendingEnrollment,
    PublicKeyHostRevoked,
    HostAlreadyLinked,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentClaimedAutonomousAgent {
    pub agent: AgentIdentity,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentHostSwitchOutcome {
    pub host: AgentHost,
    pub previous_user_id: Option<String>,
    pub revoked_agent_ids: Vec<String>,
    pub claimed_agents: Vec<AgentClaimedAutonomousAgent>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentHostRotationOutcome {
    Rotated(Box<AgentHost>),
    NotFound,
    UniqueConflict,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentRegistrationBundle {
    pub host: Option<AgentHost>,
    pub agent: AgentIdentity,
    pub grants: Vec<AgentCapabilityGrant>,
    pub approval: Option<AgentApprovalRequest>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentRegistrationOutcome {
    Registered(Box<AgentRegistrationBundle>),
    UniqueConflict,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentRevocationOutcome {
    pub agent: AgentIdentity,
    pub grants_revoked: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentCleanupOutcome {
    pub agent_ids: Vec<String>,
    pub approval_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentKeyRotationOutcome {
    Rotated(Box<AgentIdentity>),
    NotFound,
    UniqueConflict,
}

#[async_trait]
pub trait AgentAuthStore: Send + Sync {
    async fn create_host(
        &self,
        host: AgentHost,
    ) -> Result<AgentStoreCreateOutcome<AgentHost>, AuthError>;
    async fn find_host(&self, id: &str) -> Result<Option<AgentHost>, AuthError>;
    async fn find_host_by_kid(&self, kid: &str) -> Result<Option<AgentHost>, AuthError>;
    async fn find_host_by_public_key(
        &self,
        public_key: &str,
    ) -> Result<Option<AgentHost>, AuthError>;
    async fn find_host_by_enrollment_token_hash(
        &self,
        hash: &str,
    ) -> Result<Option<AgentHost>, AuthError>;
    async fn list_hosts_for_user(&self, user_id: &str) -> Result<Vec<AgentHost>, AuthError>;
    async fn update_host(&self, host: AgentHost) -> Result<Option<AgentHost>, AuthError>;
    async fn enroll_host(
        &self,
        token_hash: &str,
        enrollment: AgentHostEnrollment,
    ) -> Result<AgentHostEnrollmentOutcome, AuthError>;
    async fn revoke_host_cascade(
        &self,
        host_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AgentHost>, AuthError>;
    async fn switch_host_account_cascade(
        &self,
        host_id: &str,
        user_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AgentHostSwitchOutcome>, AuthError>;
    async fn rotate_host_key(
        &self,
        old_id: &str,
        new_id: &str,
        public_key: String,
        kid: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<AgentHostRotationOutcome, AuthError>;

    async fn create_agent(
        &self,
        agent: AgentIdentity,
    ) -> Result<AgentStoreCreateOutcome<AgentIdentity>, AuthError>;
    async fn find_agent(&self, id: &str) -> Result<Option<AgentIdentity>, AuthError>;
    async fn find_agent_by_kid(&self, kid: &str) -> Result<Option<AgentIdentity>, AuthError>;
    async fn list_agents_for_user(&self, user_id: &str) -> Result<Vec<AgentIdentity>, AuthError>;
    async fn list_agents_for_host(&self, host_id: &str) -> Result<Vec<AgentIdentity>, AuthError>;
    async fn update_agent(&self, agent: AgentIdentity) -> Result<Option<AgentIdentity>, AuthError>;
    async fn register_agent_bundle(
        &self,
        bundle: AgentRegistrationBundle,
    ) -> Result<AgentRegistrationOutcome, AuthError>;
    async fn revoke_agent_cascade(
        &self,
        agent_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AgentRevocationOutcome>, AuthError>;
    async fn reactivate_agent_replace_grants(
        &self,
        agent: AgentIdentity,
        grants: Vec<AgentCapabilityGrant>,
    ) -> Result<Option<AgentIdentity>, AuthError>;
    async fn cleanup_expired_for_user(
        &self,
        user_id: &str,
        now: DateTime<Utc>,
    ) -> Result<AgentCleanupOutcome, AuthError>;
    async fn rotate_agent_key(
        &self,
        agent_id: &str,
        public_key: String,
        kid: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<AgentKeyRotationOutcome, AuthError>;

    async fn create_grant(
        &self,
        grant: AgentCapabilityGrant,
    ) -> Result<AgentStoreCreateOutcome<AgentCapabilityGrant>, AuthError>;
    async fn find_grant(
        &self,
        agent_id: &str,
        capability: &str,
    ) -> Result<Option<AgentCapabilityGrant>, AuthError>;
    async fn find_grant_by_id(&self, id: &str) -> Result<Option<AgentCapabilityGrant>, AuthError>;
    async fn list_grants(&self, agent_id: &str) -> Result<Vec<AgentCapabilityGrant>, AuthError>;
    async fn update_grant(
        &self,
        grant: AgentCapabilityGrant,
    ) -> Result<Option<AgentCapabilityGrant>, AuthError>;
    async fn delete_grant(&self, id: &str) -> Result<bool, AuthError>;
    async fn consume_grant(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AuthError>;

    async fn create_approval(
        &self,
        approval: AgentApprovalRequest,
    ) -> Result<AgentStoreCreateOutcome<AgentApprovalRequest>, AuthError>;
    async fn find_approval(&self, id: &str) -> Result<Option<AgentApprovalRequest>, AuthError>;
    async fn find_approval_by_user_code_hash(
        &self,
        hash: &str,
    ) -> Result<Option<AgentApprovalRequest>, AuthError>;
    async fn list_pending_approvals(
        &self,
        user_id: &str,
    ) -> Result<Vec<AgentApprovalRequest>, AuthError>;
    async fn list_pending_approvals_for_agent(
        &self,
        agent_id: &str,
    ) -> Result<Vec<AgentApprovalRequest>, AuthError>;
    async fn update_approval(
        &self,
        approval: AgentApprovalRequest,
    ) -> Result<Option<AgentApprovalRequest>, AuthError>;

    async fn request_capabilities_atomic(
        &self,
        transition: AgentRequestCapabilitiesTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError>;
    async fn resolve_approval_atomic(
        &self,
        transition: AgentResolveApprovalTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError>;
    async fn grant_capabilities_atomic(
        &self,
        transition: AgentGrantCapabilitiesTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError>;
    async fn revoke_capabilities_atomic(
        &self,
        transition: AgentRevokeCapabilitiesTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError>;
}
