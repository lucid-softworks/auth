use super::{
    PostgresAgentAuthStore, agent, agent_lifecycle, approval, enrollment, grant, host,
    host_lifecycle, transition,
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
impl AgentAuthStore for PostgresAgentAuthStore {
    async fn create_host(
        &self,
        host: AgentHost,
    ) -> Result<AgentStoreCreateOutcome<AgentHost>, AuthError> {
        host::create(self, host).await
    }

    async fn find_host(&self, id: &str) -> Result<Option<AgentHost>, AuthError> {
        host::find(self, "id", id).await
    }

    async fn find_host_by_kid(&self, kid: &str) -> Result<Option<AgentHost>, AuthError> {
        host::find(self, "kid", kid).await
    }

    async fn find_host_by_public_key(
        &self,
        public_key: &str,
    ) -> Result<Option<AgentHost>, AuthError> {
        host::find(self, "publicKey", public_key).await
    }

    async fn find_host_by_enrollment_token_hash(
        &self,
        hash: &str,
    ) -> Result<Option<AgentHost>, AuthError> {
        host::find(self, "enrollmentTokenHash", hash).await
    }

    async fn list_hosts_for_user(&self, user_id: Uuid) -> Result<Vec<AgentHost>, AuthError> {
        host::list_for_user(self, user_id).await
    }

    async fn update_host(&self, host: AgentHost) -> Result<Option<AgentHost>, AuthError> {
        host::update(self, host).await
    }

    async fn enroll_host(
        &self,
        token_hash: &str,
        enrollment: AgentHostEnrollment,
    ) -> Result<AgentHostEnrollmentOutcome, AuthError> {
        enrollment::enroll(self, token_hash, enrollment).await
    }

    async fn revoke_host_cascade(
        &self,
        host_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AgentHost>, AuthError> {
        host_lifecycle::revoke_cascade(self, host_id, now).await
    }

    async fn switch_host_account_cascade(
        &self,
        host_id: &str,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<AgentHostSwitchOutcome>, AuthError> {
        host_lifecycle::switch_account_cascade(self, host_id, user_id, now).await
    }

    async fn rotate_host_key(
        &self,
        old_id: &str,
        new_id: &str,
        public_key: String,
        kid: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<AgentHostRotationOutcome, AuthError> {
        host_lifecycle::rotate_key(self, old_id, new_id, public_key, kid, now).await
    }

    async fn create_agent(
        &self,
        agent: AgentIdentity,
    ) -> Result<AgentStoreCreateOutcome<AgentIdentity>, AuthError> {
        agent::create(self, agent).await
    }

    async fn find_agent(&self, id: &str) -> Result<Option<AgentIdentity>, AuthError> {
        agent::find(self, "id", id).await
    }

    async fn find_agent_by_kid(&self, kid: &str) -> Result<Option<AgentIdentity>, AuthError> {
        agent::find(self, "kid", kid).await
    }

    async fn list_agents_for_user(&self, user_id: Uuid) -> Result<Vec<AgentIdentity>, AuthError> {
        agent::list_for_user(self, user_id).await
    }

    async fn list_agents_for_host(&self, host_id: &str) -> Result<Vec<AgentIdentity>, AuthError> {
        agent::list_for_host(self, host_id).await
    }

    async fn update_agent(&self, agent: AgentIdentity) -> Result<Option<AgentIdentity>, AuthError> {
        agent::update(self, agent).await
    }

    async fn register_agent_bundle(
        &self,
        bundle: AgentRegistrationBundle,
    ) -> Result<AgentRegistrationOutcome, AuthError> {
        agent_lifecycle::register(self, bundle).await
    }

    async fn revoke_agent_cascade(
        &self,
        agent_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AgentRevocationOutcome>, AuthError> {
        agent_lifecycle::revoke(self, agent_id, now).await
    }

    async fn reactivate_agent_replace_grants(
        &self,
        agent: AgentIdentity,
        grants: Vec<AgentCapabilityGrant>,
    ) -> Result<Option<AgentIdentity>, AuthError> {
        agent_lifecycle::reactivate(self, agent, grants).await
    }

    async fn cleanup_expired_for_user(
        &self,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<AgentCleanupOutcome, AuthError> {
        agent_lifecycle::cleanup(self, user_id, now).await
    }

    async fn rotate_agent_key(
        &self,
        agent_id: &str,
        public_key: String,
        kid: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<AgentKeyRotationOutcome, AuthError> {
        agent_lifecycle::rotate_key(self, agent_id, public_key, kid, now).await
    }

    async fn create_grant(
        &self,
        grant: AgentCapabilityGrant,
    ) -> Result<AgentStoreCreateOutcome<AgentCapabilityGrant>, AuthError> {
        grant::create(self, grant).await
    }

    async fn find_grant(
        &self,
        agent_id: &str,
        capability: &str,
    ) -> Result<Option<AgentCapabilityGrant>, AuthError> {
        grant::find(self, agent_id, capability).await
    }
    async fn find_grant_by_id(&self, id: &str) -> Result<Option<AgentCapabilityGrant>, AuthError> {
        grant::find_by_id(self, id).await
    }

    async fn list_grants(&self, agent_id: &str) -> Result<Vec<AgentCapabilityGrant>, AuthError> {
        grant::list(self, agent_id).await
    }

    async fn update_grant(
        &self,
        grant: AgentCapabilityGrant,
    ) -> Result<Option<AgentCapabilityGrant>, AuthError> {
        grant::update(self, grant).await
    }

    async fn delete_grant(&self, id: &str) -> Result<bool, AuthError> {
        grant::delete(self, id).await
    }
    async fn consume_grant(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AuthError> {
        grant::consume(self, id, now).await
    }

    async fn create_approval(
        &self,
        approval: AgentApprovalRequest,
    ) -> Result<AgentStoreCreateOutcome<AgentApprovalRequest>, AuthError> {
        approval::create(self, approval).await
    }

    async fn find_approval(&self, id: &str) -> Result<Option<AgentApprovalRequest>, AuthError> {
        approval::find(self, "id", id).await
    }

    async fn find_approval_by_user_code_hash(
        &self,
        hash: &str,
    ) -> Result<Option<AgentApprovalRequest>, AuthError> {
        approval::find(self, "userCodeHash", hash).await
    }

    async fn list_pending_approvals(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<AgentApprovalRequest>, AuthError> {
        approval::list_pending_for_user(self, user_id).await
    }

    async fn list_pending_approvals_for_agent(
        &self,
        agent_id: &str,
    ) -> Result<Vec<AgentApprovalRequest>, AuthError> {
        approval::list_pending_for_agent(self, agent_id).await
    }

    async fn update_approval(
        &self,
        approval: AgentApprovalRequest,
    ) -> Result<Option<AgentApprovalRequest>, AuthError> {
        approval::update(self, approval).await
    }

    async fn request_capabilities_atomic(
        &self,
        value: AgentRequestCapabilitiesTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError> {
        transition::apply(self, value.0).await
    }
    async fn resolve_approval_atomic(
        &self,
        value: AgentResolveApprovalTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError> {
        transition::apply(self, value.0).await
    }
    async fn grant_capabilities_atomic(
        &self,
        value: AgentGrantCapabilitiesTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError> {
        transition::apply(self, value.0).await
    }
    async fn revoke_capabilities_atomic(
        &self,
        value: AgentRevokeCapabilitiesTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError> {
        transition::apply(self, value.0).await
    }
}
