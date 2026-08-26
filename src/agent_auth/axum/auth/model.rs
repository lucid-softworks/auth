use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{
    AgentCapabilityGrant, AgentGrantStatus, AgentHost, AgentHostSession, AgentHostSessionIdentity,
    AgentIdentity, AgentMode, AgentSession, AgentSessionGrant, AgentSessionHost,
    AgentSessionIdentity, AgentSessionUser, AuthUser,
};

pub(in crate::agent_auth::axum) fn agent_session(
    agent: &AgentIdentity,
    host: Option<&AgentHost>,
    user_id: Option<String>,
    user: AgentSessionUser,
    grants: Vec<AgentCapabilityGrant>,
) -> AgentSession {
    AgentSession {
        r#type: agent.mode,
        agent_id: agent.id.clone(),
        user_id,
        agent: AgentSessionIdentity {
            id: agent.id.clone(),
            name: agent.name.clone(),
            mode: agent.mode,
            capability_grants: grants.into_iter().map(session_grant).collect(),
            host_id: agent.host_id.clone(),
            created_at: agent.created_at,
            activated_at: agent.activated_at,
            metadata: agent.metadata.clone(),
        },
        host: host.map(|host| AgentSessionHost {
            id: host.id.clone(),
            user_id: host.user_id.clone(),
            status: host.status.to_string(),
        }),
        user,
    }
}

fn session_grant(grant: AgentCapabilityGrant) -> AgentSessionGrant {
    AgentSessionGrant {
        capability: grant.capability,
        constraints: grant.constraints,
        granted_by: grant.granted_by,
        status: grant.status.to_string(),
    }
}

pub(super) fn agent_session_user(user: AuthUser) -> AgentSessionUser {
    let mut attributes = serde_json::to_value(&user)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    attributes.remove("id");
    attributes.remove("name");
    attributes.remove("email");
    AgentSessionUser {
        id: user.id.to_string(),
        name: user.name,
        email: user.email,
        attributes,
    }
}

#[derive(Debug, Clone)]
pub(super) struct AuthenticatedAgent {
    pub agent: AgentIdentity,
    pub session: AgentSession,
}

pub(in crate::agent_auth::axum) fn host_session(host: AgentHost) -> AgentHostSession {
    AgentHostSession {
        host: AgentHostSessionIdentity {
            id: host.id,
            user_id: host.user_id,
            default_capabilities: host.default_capabilities,
            status: host.status.to_string(),
        },
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(in crate::agent_auth::axum) enum IntrospectionResponse {
    Inactive {
        active: bool,
    },
    Active {
        active: bool,
        agent_id: String,
        host_id: String,
        user_id: Option<String>,
        agent_capability_grants: Vec<IntrospectionGrant>,
        mode: AgentMode,
        expires_at: Option<DateTime<Utc>>,
    },
}

impl IntrospectionResponse {
    pub(super) fn inactive() -> Self {
        Self::Inactive { active: false }
    }

    pub(super) fn active(
        agent_id: String,
        host_id: String,
        user_id: Option<String>,
        agent_capability_grants: Vec<IntrospectionGrant>,
        mode: AgentMode,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self::Active {
            active: true,
            agent_id,
            host_id,
            user_id,
            agent_capability_grants,
            mode,
            expires_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub(in crate::agent_auth::axum) struct IntrospectionGrant {
    pub capability: String,
    pub status: AgentGrantStatus,
}

impl From<AgentCapabilityGrant> for IntrospectionGrant {
    fn from(grant: AgentCapabilityGrant) -> Self {
        Self {
            capability: grant.capability,
            status: grant.status,
        }
    }
}
