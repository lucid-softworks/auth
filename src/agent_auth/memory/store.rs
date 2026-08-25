use super::{
    MemoryAgentAuthStore, agent, agent_lifecycle, approval, grant, host, lifecycle, rotation,
    transition,
};
use crate::{
    AuthError,
    agent_auth::{
        AgentApprovalRequest, AgentAuthStore, AgentCapabilityGrant,
        AgentCapabilityTransitionOutcome, AgentCleanupOutcome, AgentGrantCapabilitiesTransition,
        AgentHost, AgentHostEnrollment, AgentHostEnrollmentOutcome, AgentHostRotationOutcome,
        AgentHostSwitchOutcome, AgentIdentity, AgentKeyRotationOutcome, AgentRegistrationBundle,
        AgentRegistrationOutcome, AgentRequestCapabilitiesTransition,
        AgentResolveApprovalTransition, AgentRevocationOutcome, AgentRevokeCapabilitiesTransition,
        AgentStoreCreateOutcome,
    },
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[async_trait]
impl AgentAuthStore for MemoryAgentAuthStore {
    async fn create_host(
        &self,
        value: AgentHost,
    ) -> Result<AgentStoreCreateOutcome<AgentHost>, AuthError> {
        host::create(self, value)
    }
    async fn find_host(&self, id: &str) -> Result<Option<AgentHost>, AuthError> {
        host::find(self, |value| value.id == id)
    }
    async fn find_host_by_kid(&self, kid: &str) -> Result<Option<AgentHost>, AuthError> {
        host::find(self, |value| value.kid.as_deref() == Some(kid))
    }
    async fn find_host_by_public_key(&self, key: &str) -> Result<Option<AgentHost>, AuthError> {
        host::find(self, |value| value.public_key.as_deref() == Some(key))
    }
    async fn find_host_by_enrollment_token_hash(
        &self,
        hash: &str,
    ) -> Result<Option<AgentHost>, AuthError> {
        host::find(self, |value| {
            value.enrollment_token_hash.as_deref() == Some(hash)
        })
    }
    async fn list_hosts_for_user(&self, user_id: Uuid) -> Result<Vec<AgentHost>, AuthError> {
        host::list_for_user(self, user_id)
    }
    async fn update_host(&self, value: AgentHost) -> Result<Option<AgentHost>, AuthError> {
        host::update(self, value)
    }
    async fn enroll_host(
        &self,
        hash: &str,
        value: AgentHostEnrollment,
    ) -> Result<AgentHostEnrollmentOutcome, AuthError> {
        lifecycle::enroll(self, hash, value)
    }
    async fn revoke_host_cascade(
        &self,
        id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AgentHost>, AuthError> {
        lifecycle::revoke(self, id, now)
    }
    async fn switch_host_account_cascade(
        &self,
        id: &str,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<AgentHostSwitchOutcome>, AuthError> {
        lifecycle::switch_account(self, id, user_id, now)
    }
    async fn rotate_host_key(
        &self,
        old_id: &str,
        new_id: &str,
        key: String,
        kid: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<AgentHostRotationOutcome, AuthError> {
        rotation::rotate_key(self, old_id, new_id, key, kid, now)
    }
    async fn create_agent(
        &self,
        value: AgentIdentity,
    ) -> Result<AgentStoreCreateOutcome<AgentIdentity>, AuthError> {
        agent::create(self, value)
    }
    async fn find_agent(&self, id: &str) -> Result<Option<AgentIdentity>, AuthError> {
        agent::find(self, |value| value.id == id)
    }
    async fn find_agent_by_kid(&self, kid: &str) -> Result<Option<AgentIdentity>, AuthError> {
        agent::find(self, |value| value.kid.as_deref() == Some(kid))
    }
    async fn list_agents_for_user(&self, user_id: Uuid) -> Result<Vec<AgentIdentity>, AuthError> {
        agent::list(self, |value| value.user_id == Some(user_id))
    }
    async fn list_agents_for_host(&self, host_id: &str) -> Result<Vec<AgentIdentity>, AuthError> {
        agent::list(self, |value| value.host_id == host_id)
    }
    async fn update_agent(&self, value: AgentIdentity) -> Result<Option<AgentIdentity>, AuthError> {
        agent::update(self, value)
    }
    async fn register_agent_bundle(
        &self,
        bundle: AgentRegistrationBundle,
    ) -> Result<AgentRegistrationOutcome, AuthError> {
        agent_lifecycle::register(self, bundle)
    }
    async fn revoke_agent_cascade(
        &self,
        agent_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AgentRevocationOutcome>, AuthError> {
        agent_lifecycle::revoke(self, agent_id, now)
    }
    async fn reactivate_agent_replace_grants(
        &self,
        agent: AgentIdentity,
        grants: Vec<AgentCapabilityGrant>,
    ) -> Result<Option<AgentIdentity>, AuthError> {
        agent_lifecycle::reactivate(self, agent, grants)
    }
    async fn cleanup_expired_for_user(
        &self,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<AgentCleanupOutcome, AuthError> {
        agent_lifecycle::cleanup(self, user_id, now)
    }
    async fn rotate_agent_key(
        &self,
        agent_id: &str,
        public_key: String,
        kid: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<AgentKeyRotationOutcome, AuthError> {
        agent_lifecycle::rotate_key(self, agent_id, public_key, kid, now)
    }
    async fn create_grant(
        &self,
        value: AgentCapabilityGrant,
    ) -> Result<AgentStoreCreateOutcome<AgentCapabilityGrant>, AuthError> {
        grant::create(self, value)
    }
    async fn find_grant(
        &self,
        agent_id: &str,
        capability: &str,
    ) -> Result<Option<AgentCapabilityGrant>, AuthError> {
        grant::find(self, agent_id, capability)
    }
    async fn find_grant_by_id(&self, id: &str) -> Result<Option<AgentCapabilityGrant>, AuthError> {
        grant::find_by_id(self, id)
    }
    async fn list_grants(&self, agent_id: &str) -> Result<Vec<AgentCapabilityGrant>, AuthError> {
        grant::list(self, agent_id)
    }
    async fn update_grant(
        &self,
        value: AgentCapabilityGrant,
    ) -> Result<Option<AgentCapabilityGrant>, AuthError> {
        grant::update(self, value)
    }
    async fn delete_grant(&self, id: &str) -> Result<bool, AuthError> {
        grant::delete(self, id)
    }
    async fn consume_grant(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AuthError> {
        grant::consume(self, id, now)
    }
    async fn create_approval(
        &self,
        value: AgentApprovalRequest,
    ) -> Result<AgentStoreCreateOutcome<AgentApprovalRequest>, AuthError> {
        approval::create(self, value)
    }
    async fn find_approval(&self, id: &str) -> Result<Option<AgentApprovalRequest>, AuthError> {
        approval::find(self, |value| value.id == id)
    }
    async fn find_approval_by_user_code_hash(
        &self,
        hash: &str,
    ) -> Result<Option<AgentApprovalRequest>, AuthError> {
        approval::find(self, |value| value.user_code_hash.as_deref() == Some(hash))
    }
    async fn list_pending_approvals(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<AgentApprovalRequest>, AuthError> {
        approval::list_pending(self, user_id)
    }
    async fn list_pending_approvals_for_agent(
        &self,
        agent_id: &str,
    ) -> Result<Vec<AgentApprovalRequest>, AuthError> {
        approval::list_pending_for_agent(self, agent_id)
    }
    async fn update_approval(
        &self,
        value: AgentApprovalRequest,
    ) -> Result<Option<AgentApprovalRequest>, AuthError> {
        approval::update(self, value)
    }

    async fn request_capabilities_atomic(
        &self,
        value: AgentRequestCapabilitiesTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError> {
        transition::apply(self, value.0)
    }
    async fn resolve_approval_atomic(
        &self,
        value: AgentResolveApprovalTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError> {
        transition::apply(self, value.0)
    }
    async fn grant_capabilities_atomic(
        &self,
        value: AgentGrantCapabilitiesTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError> {
        transition::apply(self, value.0)
    }
    async fn revoke_capabilities_atomic(
        &self,
        value: AgentRevokeCapabilitiesTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError> {
        transition::apply(self, value.0)
    }
}
