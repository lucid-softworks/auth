mod atomic;
mod codec;
mod query;
mod record;

use self::query::{eq, find, first_by_id, list, list_pending};
use super::MongoStore;
use crate::{
    AgentApprovalRequest, AgentAuthStore, AgentCapabilityGrant, AgentCapabilityTransitionOutcome,
    AgentCleanupOutcome, AgentGrantCapabilitiesTransition, AgentHost, AgentHostEnrollment,
    AgentHostEnrollmentOutcome, AgentHostRotationOutcome, AgentHostSwitchOutcome, AgentIdentity,
    AgentKeyRotationOutcome, AgentRegistrationBundle, AgentRegistrationOutcome,
    AgentRequestCapabilitiesTransition, AgentResolveApprovalTransition, AgentRevocationOutcome,
    AgentRevokeCapabilitiesTransition, AgentStoreCreateOutcome, AuthError,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

macro_rules! mutate {
    ($store:expr, |$memory:ident| $operation:expr) => {{
        let mut connection = record::begin_immediate($store).await?;
        let work = async {
            let before = record::load_snapshot($store, &mut connection).await?;
            let $memory = crate::MemoryAgentAuthStore::from_snapshot(before.clone());
            let result = $operation.await?;
            let after = $memory.snapshot()?;
            record::sync_snapshot($store, &mut connection, &before, &after).await?;
            Ok::<_, AuthError>(result)
        }
        .await;
        match work {
            Ok(result) => record::commit(connection).await.map(|()| result),
            Err(error) => {
                record::rollback(connection).await;
                Err(error)
            }
        }
    }};
}

#[async_trait]
impl AgentAuthStore for MongoStore {
    async fn create_host(
        &self,
        value: AgentHost,
    ) -> Result<AgentStoreCreateOutcome<AgentHost>, AuthError> {
        let value = record::normalize_host(value);
        mutate!(self, |memory| memory.create_host(value))
    }
    async fn find_host(&self, id: &str) -> Result<Option<AgentHost>, AuthError> {
        find(self, "agentHost", "id", id, record::decode_host).await
    }
    async fn find_host_by_kid(&self, kid: &str) -> Result<Option<AgentHost>, AuthError> {
        find(self, "agentHost", "kid", kid, record::decode_host).await
    }
    async fn find_host_by_public_key(&self, key: &str) -> Result<Option<AgentHost>, AuthError> {
        find(self, "agentHost", "publicKey", key, record::decode_host).await
    }
    async fn find_host_by_enrollment_token_hash(
        &self,
        hash: &str,
    ) -> Result<Option<AgentHost>, AuthError> {
        find(
            self,
            "agentHost",
            "enrollmentTokenHash",
            hash,
            record::decode_host,
        )
        .await
    }
    async fn list_hosts_for_user(&self, user_id: &str) -> Result<Vec<AgentHost>, AuthError> {
        list(self, "agentHost", "userId", user_id, record::decode_host).await
    }
    async fn update_host(&self, value: AgentHost) -> Result<Option<AgentHost>, AuthError> {
        let value = record::normalize_host(value);
        mutate!(self, |memory| memory.update_host(value))
    }
    async fn enroll_host(
        &self,
        hash: &str,
        value: AgentHostEnrollment,
    ) -> Result<AgentHostEnrollmentOutcome, AuthError> {
        let value = AgentHostEnrollment {
            now: record::millis(value.now),
            expires_at: value.expires_at.map(record::millis),
            ..value
        };
        mutate!(self, |memory| memory.enroll_host(hash, value))
    }
    async fn revoke_host_cascade(
        &self,
        id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AgentHost>, AuthError> {
        let now = record::millis(now);
        mutate!(self, |memory| memory.revoke_host_cascade(id, now))
    }
    async fn switch_host_account_cascade(
        &self,
        id: &str,
        user_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AgentHostSwitchOutcome>, AuthError> {
        let now = record::millis(now);
        mutate!(self, |memory| memory
            .switch_host_account_cascade(id, user_id, now))
    }
    async fn rotate_host_key(
        &self,
        old_id: &str,
        new_id: &str,
        key: String,
        kid: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<AgentHostRotationOutcome, AuthError> {
        let now = record::millis(now);
        mutate!(self, |memory| memory
            .rotate_host_key(old_id, new_id, key, kid, now))
    }

    async fn create_agent(
        &self,
        value: AgentIdentity,
    ) -> Result<AgentStoreCreateOutcome<AgentIdentity>, AuthError> {
        let value = record::normalize_agent(value);
        mutate!(self, |memory| memory.create_agent(value))
    }
    async fn find_agent(&self, id: &str) -> Result<Option<AgentIdentity>, AuthError> {
        find(self, "agent", "id", id, record::decode_agent).await
    }
    async fn find_agent_by_kid(&self, kid: &str) -> Result<Option<AgentIdentity>, AuthError> {
        find(self, "agent", "kid", kid, record::decode_agent).await
    }
    async fn list_agents_for_user(&self, user_id: &str) -> Result<Vec<AgentIdentity>, AuthError> {
        list(self, "agent", "userId", user_id, record::decode_agent).await
    }
    async fn list_agents_for_host(&self, host_id: &str) -> Result<Vec<AgentIdentity>, AuthError> {
        list(self, "agent", "hostId", host_id, record::decode_agent).await
    }
    async fn update_agent(&self, value: AgentIdentity) -> Result<Option<AgentIdentity>, AuthError> {
        let value = record::normalize_agent(value);
        mutate!(self, |memory| memory.update_agent(value))
    }
    async fn register_agent_bundle(
        &self,
        value: AgentRegistrationBundle,
    ) -> Result<AgentRegistrationOutcome, AuthError> {
        let value = AgentRegistrationBundle {
            host: value.host.map(record::normalize_host),
            agent: record::normalize_agent(value.agent),
            grants: value
                .grants
                .into_iter()
                .map(record::normalize_grant)
                .collect(),
            approval: value.approval.map(record::normalize_approval),
        };
        mutate!(self, |memory| memory.register_agent_bundle(value))
    }
    async fn revoke_agent_cascade(
        &self,
        id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AgentRevocationOutcome>, AuthError> {
        let now = record::millis(now);
        mutate!(self, |memory| memory.revoke_agent_cascade(id, now))
    }
    async fn reactivate_agent_replace_grants(
        &self,
        agent: AgentIdentity,
        grants: Vec<AgentCapabilityGrant>,
    ) -> Result<Option<AgentIdentity>, AuthError> {
        let agent = record::normalize_agent(agent);
        let grants = grants.into_iter().map(record::normalize_grant).collect();
        mutate!(self, |memory| memory
            .reactivate_agent_replace_grants(agent, grants))
    }
    async fn cleanup_expired_for_user(
        &self,
        user_id: &str,
        now: DateTime<Utc>,
    ) -> Result<AgentCleanupOutcome, AuthError> {
        let now = record::millis(now);
        mutate!(self, |memory| memory.cleanup_expired_for_user(user_id, now))
    }
    async fn rotate_agent_key(
        &self,
        id: &str,
        key: String,
        kid: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<AgentKeyRotationOutcome, AuthError> {
        let now = record::millis(now);
        mutate!(self, |memory| memory.rotate_agent_key(id, key, kid, now))
    }

    async fn create_grant(
        &self,
        value: AgentCapabilityGrant,
    ) -> Result<AgentStoreCreateOutcome<AgentCapabilityGrant>, AuthError> {
        let value = record::normalize_grant(value);
        mutate!(self, |memory| memory.create_grant(value))
    }
    async fn find_grant(
        &self,
        agent_id: &str,
        capability: &str,
    ) -> Result<Option<AgentCapabilityGrant>, AuthError> {
        self.find_records(
            "agentCapabilityGrant",
            &[eq("agentId", agent_id), eq("capability", capability)],
            &first_by_id(),
        )
        .await?
        .into_iter()
        .next()
        .map(record::decode_grant)
        .transpose()
    }
    async fn find_grant_by_id(&self, id: &str) -> Result<Option<AgentCapabilityGrant>, AuthError> {
        find(self, "agentCapabilityGrant", "id", id, record::decode_grant).await
    }
    async fn list_grants(&self, agent_id: &str) -> Result<Vec<AgentCapabilityGrant>, AuthError> {
        list(
            self,
            "agentCapabilityGrant",
            "agentId",
            agent_id,
            record::decode_grant,
        )
        .await
    }
    async fn update_grant(
        &self,
        value: AgentCapabilityGrant,
    ) -> Result<Option<AgentCapabilityGrant>, AuthError> {
        let value = record::normalize_grant(value);
        mutate!(self, |memory| memory.update_grant(value))
    }
    async fn delete_grant(&self, id: &str) -> Result<bool, AuthError> {
        mutate!(self, |memory| memory.delete_grant(id))
    }
    async fn consume_grant(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AuthError> {
        let now = record::millis(now);
        mutate!(self, |memory| memory.consume_grant(id, now))
    }

    async fn create_approval(
        &self,
        value: AgentApprovalRequest,
    ) -> Result<AgentStoreCreateOutcome<AgentApprovalRequest>, AuthError> {
        let value = record::normalize_approval(value);
        mutate!(self, |memory| memory.create_approval(value))
    }
    async fn find_approval(&self, id: &str) -> Result<Option<AgentApprovalRequest>, AuthError> {
        find(self, "approvalRequest", "id", id, record::decode_approval).await
    }
    async fn find_approval_by_user_code_hash(
        &self,
        hash: &str,
    ) -> Result<Option<AgentApprovalRequest>, AuthError> {
        find(
            self,
            "approvalRequest",
            "userCodeHash",
            hash,
            record::decode_approval,
        )
        .await
    }
    async fn list_pending_approvals(
        &self,
        user_id: &str,
    ) -> Result<Vec<AgentApprovalRequest>, AuthError> {
        list_pending(self, "userId", user_id).await
    }
    async fn list_pending_approvals_for_agent(
        &self,
        agent_id: &str,
    ) -> Result<Vec<AgentApprovalRequest>, AuthError> {
        list_pending(self, "agentId", agent_id).await
    }
    async fn update_approval(
        &self,
        value: AgentApprovalRequest,
    ) -> Result<Option<AgentApprovalRequest>, AuthError> {
        let value = record::normalize_approval(value);
        mutate!(self, |memory| memory.update_approval(value))
    }

    async fn request_capabilities_atomic(
        &self,
        value: AgentRequestCapabilitiesTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError> {
        atomic::transition(self, value.0).await
    }
    async fn resolve_approval_atomic(
        &self,
        value: AgentResolveApprovalTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError> {
        atomic::transition(self, value.0).await
    }
    async fn grant_capabilities_atomic(
        &self,
        value: AgentGrantCapabilitiesTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError> {
        atomic::transition(self, value.0).await
    }
    async fn revoke_capabilities_atomic(
        &self,
        value: AgentRevokeCapabilitiesTransition,
    ) -> Result<AgentCapabilityTransitionOutcome, AuthError> {
        atomic::transition(self, value.0).await
    }
}
