mod maintenance;
mod registration;
mod status;

pub(super) use maintenance::{cleanup, rotate_key};
pub(super) use registration::register;
pub(super) use status::{reactivate, revoke};

#[cfg(test)]
mod fixtures {
    use crate::agent_auth::{
        AgentApprovalMethod, AgentApprovalRequest, AgentApprovalStatus, AgentCapabilityGrant,
        AgentGrantStatus, AgentHost, AgentHostStatus, AgentIdentity, AgentMode, AgentStatus,
    };
    use chrono::{DateTime, Duration, Utc};
    use uuid::Uuid;

    pub(super) fn host(id: &str, user_id: Uuid, now: DateTime<Utc>) -> AgentHost {
        AgentHost {
            id: id.into(),
            name: Some("Host".into()),
            user_id: Some(user_id),
            default_capabilities: vec!["files.read".into()],
            public_key: Some(format!("host-key-{id}")),
            kid: Some(format!("host-kid-{id}")),
            jwks_url: None,
            enrollment_token_hash: None,
            enrollment_token_expires_at: None,
            status: AgentHostStatus::Active,
            activated_at: Some(now),
            expires_at: None,
            last_used_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub(super) fn agent(
        id: &str,
        host_id: &str,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> AgentIdentity {
        AgentIdentity {
            id: id.into(),
            name: "Agent".into(),
            user_id: Some(user_id),
            host_id: host_id.into(),
            status: AgentStatus::Active,
            mode: AgentMode::Delegated,
            public_key: format!("agent-key-{id}"),
            kid: Some(format!("agent-kid-{id}")),
            jwks_url: None,
            last_used_at: None,
            activated_at: Some(now),
            expires_at: None,
            metadata: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub(super) fn grant(
        id: &str,
        agent_id: &str,
        capability: &str,
        now: DateTime<Utc>,
    ) -> AgentCapabilityGrant {
        AgentCapabilityGrant {
            id: id.into(),
            agent_id: agent_id.into(),
            capability: capability.into(),
            constraints: None,
            denied_by: None,
            granted_by: None,
            expires_at: None,
            status: AgentGrantStatus::Active,
            reason: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub(super) fn approval(
        id: &str,
        agent_id: &str,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> AgentApprovalRequest {
        AgentApprovalRequest {
            id: id.into(),
            method: AgentApprovalMethod::DeviceAuthorization,
            agent_id: Some(agent_id.into()),
            host_id: Some("host-new".into()),
            user_id: Some(user_id),
            capabilities: Some("files.read".into()),
            status: AgentApprovalStatus::Pending,
            user_code_hash: Some(format!("code-{id}")),
            login_hint: None,
            binding_message: None,
            client_notification_token: None,
            client_notification_endpoint: None,
            delivery_mode: None,
            interval: 5.0,
            last_polled_at: None,
            expires_at: now + Duration::minutes(5),
            created_at: now,
            updated_at: now,
        }
    }
}
