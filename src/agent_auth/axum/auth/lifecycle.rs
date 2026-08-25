use chrono::{DateTime, Utc};

use super::{AgentAuthState, AgentAuthenticationError};
use crate::{
    AgentAuthConfig, AgentCapabilityGrant, AgentGrantStatus, AgentGrantTtlContext, AgentIdentity,
    AgentStatus,
};
use serde_json::json;
use uuid::Uuid;

pub(super) fn validate_agent_status(agent: &AgentIdentity) -> Result<(), AgentAuthenticationError> {
    match agent.status {
        AgentStatus::Revoked => return Err(AgentAuthenticationError::agent_revoked()),
        AgentStatus::Claimed => return Err(AgentAuthenticationError::agent_claimed()),
        AgentStatus::Pending => return Err(AgentAuthenticationError::agent_pending()),
        AgentStatus::Rejected => return Err(AgentAuthenticationError::agent_rejected()),
        AgentStatus::Active | AgentStatus::Expired => {}
    }
    Ok(())
}

pub(super) async fn enforce_absolute_lifetime(
    state: &AgentAuthState,
    agent: &AgentIdentity,
    now: DateTime<Utc>,
) -> Result<(), AgentAuthenticationError> {
    if state.config.absolute_lifetime == 0
        || now < agent.created_at + duration(state.config.absolute_lifetime)
    {
        return Ok(());
    }
    state
        .store
        .revoke_agent_cascade(&agent.id, now)
        .await
        .map_err(AgentAuthenticationError::storage)?
        .ok_or_else(AgentAuthenticationError::agent_not_found)?;
    Err(AgentAuthenticationError::absolute_lifetime())
}

pub(super) fn needs_reactivation(agent: &AgentIdentity, config: &AgentAuthConfig) -> bool {
    let now = Utc::now();
    agent.status == AgentStatus::Expired
        || agent.expires_at.is_some_and(|expires| expires <= now)
        || (config.agent_max_lifetime > 0
            && agent
                .activated_at
                .unwrap_or(agent.created_at)
                .checked_add_signed(duration(config.agent_max_lifetime))
                .is_some_and(|expires| expires <= now))
}

pub(super) async fn mark_agent_expired(
    state: &AgentAuthState,
    agent: &AgentIdentity,
    now: DateTime<Utc>,
) {
    let mut expired = agent.clone();
    expired.status = AgentStatus::Expired;
    expired.updated_at = now;
    let _ = state.store.update_agent(expired).await;
}

pub(super) async fn transparent_reactivation(
    state: &AgentAuthState,
    mut agent: AgentIdentity,
    now: DateTime<Utc>,
) -> Result<Option<AgentIdentity>, AgentAuthenticationError> {
    if agent.public_key.is_empty() {
        return Ok(None);
    }
    let Some(host) = state
        .store
        .find_host(&agent.host_id)
        .await
        .map_err(AgentAuthenticationError::storage)?
        .filter(|host| host.status != crate::AgentHostStatus::Revoked)
    else {
        return Ok(None);
    };
    let grants = reactivation_grants(state, &agent, &host.default_capabilities, now).await;
    agent.status = AgentStatus::Active;
    agent.activated_at = Some(now);
    agent.last_used_at = Some(now);
    agent.expires_at = (state.config.agent_session_ttl > 0)
        .then_some(now + duration(state.config.agent_session_ttl));
    agent.updated_at = now;
    state
        .store
        .reactivate_agent_replace_grants(agent, grants)
        .await
        .map_err(AgentAuthenticationError::storage)
}

async fn reactivation_grants(
    state: &AgentAuthState,
    agent: &AgentIdentity,
    capabilities: &[String],
    now: DateTime<Utc>,
) -> Vec<AgentCapabilityGrant> {
    let mut grants = Vec::with_capacity(capabilities.len());
    for capability in capabilities {
        let expires_at = resolve_grant_expiry(state, agent, capability, now).await;
        grants.push(AgentCapabilityGrant {
            id: Uuid::new_v4().to_string(),
            agent_id: agent.id.clone(),
            capability: capability.clone(),
            constraints: None,
            denied_by: None,
            granted_by: agent.user_id,
            expires_at,
            status: AgentGrantStatus::Active,
            reason: None,
            created_at: now,
            updated_at: now,
        });
    }
    grants
}

async fn resolve_grant_expiry(
    state: &AgentAuthState,
    agent: &AgentIdentity,
    capability: &str,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let ttl = match &state.config.resolve_grant_ttl {
        Some(resolve) => {
            resolve
                .resolve(AgentGrantTtlContext {
                    capability: capability.to_owned(),
                    agent_id: agent.id.clone(),
                    host_id: Some(agent.host_id.clone()),
                    user_id: agent.user_id,
                })
                .await
        }
        None => state
            .config
            .capabilities
            .iter()
            .find(|definition| definition.name == capability)
            .and_then(|definition| definition.grant_ttl),
    };
    ttl.map(|ttl| now + duration(ttl))
}

pub(super) fn emit_transparent_reactivation(state: &AgentAuthState, agent: &AgentIdentity) {
    super::super::events::emit(
        &state.config,
        crate::AgentAuthEvent::Audit(Box::new(crate::AgentAuthAuditEvent {
            r#type: crate::AgentAuthAuditEventType::AgentReactivated,
            fields: crate::AgentAuthEventFields {
                actor_type: Some("system".into()),
                agent_id: Some(agent.id.clone()),
                host_id: Some(agent.host_id.clone()),
                metadata: Some(serde_json::Map::from_iter([(
                    "transparent".into(),
                    json!(true),
                )])),
                ..crate::AgentAuthEventFields::default()
            },
        })),
    );
}

pub(in crate::agent_auth::axum) fn active_grants(
    mut grants: Vec<AgentCapabilityGrant>,
) -> Vec<AgentCapabilityGrant> {
    let now = Utc::now();
    grants.retain(|grant| {
        grant.status == AgentGrantStatus::Active
            && grant.expires_at.is_none_or(|expires| expires > now)
    });
    grants
}

pub(super) async fn heartbeat(state: &AgentAuthState, agent: &AgentIdentity) {
    let now = Utc::now();
    let mut updated = agent.clone();
    updated.last_used_at = Some(now);
    if state.config.agent_session_ttl > 0 {
        let mut expires = now + duration(state.config.agent_session_ttl);
        if state.config.agent_max_lifetime > 0 {
            expires = expires.min(
                agent.activated_at.unwrap_or(agent.created_at)
                    + duration(state.config.agent_max_lifetime),
            );
        }
        if state.config.absolute_lifetime > 0 {
            expires = expires.min(agent.created_at + duration(state.config.absolute_lifetime));
        }
        updated.expires_at = Some(expires);
    }
    updated.updated_at = now;
    let _ = state.store.update_agent(updated).await;
}

fn duration(seconds: u64) -> chrono::Duration {
    chrono::Duration::seconds(seconds.try_into().unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AgentAuthEvent, AgentCapabilityGrant, AgentEventCallback, AgentHost, AgentHostStatus,
        AgentIdentity, AgentMode, AgentStoreCreateOutcome, MemoryAgentAuthStore,
    };
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    fn state(config: AgentAuthConfig) -> (AgentAuthState, Arc<MemoryAgentAuthStore>) {
        let store = Arc::new(MemoryAgentAuthStore::default());
        let verifier = crate::agent_auth::axum::memory_verifier();
        let state = AgentAuthState {
            config: Arc::new(config),
            store: store.clone(),
            organization_store: None,
            host_auth: crate::agent_auth::axum::host::HostAuthState::from_verifier(
                verifier.clone(),
            ),
            verifier,
        };
        (state, store)
    }

    fn host(now: DateTime<Utc>) -> AgentHost {
        AgentHost {
            id: "host".into(),
            name: None,
            user_id: None,
            default_capabilities: vec!["current.read".into()],
            public_key: Some("host-key".into()),
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
        }
    }

    fn agent(now: DateTime<Utc>) -> AgentIdentity {
        AgentIdentity {
            id: "agent".into(),
            name: "Agent".into(),
            user_id: None,
            host_id: "host".into(),
            status: AgentStatus::Expired,
            mode: AgentMode::Autonomous,
            public_key: "{\"kty\":\"OKP\"}".into(),
            kid: Some("agent-key".into()),
            jwks_url: None,
            last_used_at: None,
            activated_at: Some(now - chrono::Duration::hours(1)),
            expires_at: Some(now - chrono::Duration::seconds(1)),
            metadata: None,
            created_at: now - chrono::Duration::hours(2),
            updated_at: now,
        }
    }

    fn grant(now: DateTime<Utc>) -> AgentCapabilityGrant {
        AgentCapabilityGrant {
            id: "old-grant".into(),
            agent_id: "agent".into(),
            capability: "old.read".into(),
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

    async fn seed(state: &AgentAuthState, now: DateTime<Utc>) {
        assert!(matches!(
            state.store.create_host(host(now)).await.unwrap(),
            AgentStoreCreateOutcome::Created(_)
        ));
        assert!(matches!(
            state.store.create_agent(agent(now)).await.unwrap(),
            AgentStoreCreateOutcome::Created(_)
        ));
        assert!(matches!(
            state.store.create_grant(grant(now)).await.unwrap(),
            AgentStoreCreateOutcome::Created(_)
        ));
    }

    #[tokio::test]
    async fn absolute_lifetime_revokes_agent_key_and_grants_before_erroring() {
        let now = Utc::now();
        let config = AgentAuthConfig {
            absolute_lifetime: 60,
            ..AgentAuthConfig::default()
        };
        let (state, _) = state(config);
        seed(&state, now).await;
        let stored = state.store.find_agent("agent").await.unwrap().unwrap();
        assert!(
            enforce_absolute_lifetime(&state, &stored, now)
                .await
                .is_err()
        );
        let revoked = state.store.find_agent("agent").await.unwrap().unwrap();
        assert_eq!(revoked.status, AgentStatus::Revoked);
        assert!(revoked.public_key.is_empty());
        assert!(revoked.kid.is_none());
        assert!(
            state
                .store
                .list_grants("agent")
                .await
                .unwrap()
                .iter()
                .all(|grant| grant.status == AgentGrantStatus::Revoked)
        );
    }

    #[tokio::test]
    async fn transparent_reactivation_replaces_grants_and_sets_session_times() {
        let now = Utc::now();
        let config = AgentAuthConfig {
            agent_session_ttl: 120,
            ..AgentAuthConfig::default()
        };
        let (state, _) = state(config);
        seed(&state, now).await;
        let expired = state.store.find_agent("agent").await.unwrap().unwrap();
        let active = transparent_reactivation(&state, expired, now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.status, AgentStatus::Active);
        assert_eq!(active.activated_at, Some(now));
        assert_eq!(active.last_used_at, Some(now));
        assert_eq!(
            active.expires_at,
            Some(now + chrono::Duration::seconds(120))
        );
        let grants = state.store.list_grants("agent").await.unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].capability, "current.read");
        assert_eq!(grants[0].status, AgentGrantStatus::Active);
    }

    #[test]
    fn expired_status_ttl_and_max_lifetime_each_require_reactivation() {
        let now = Utc::now();
        let mut config = AgentAuthConfig::default();
        let expired = agent(now);
        assert!(needs_reactivation(&expired, &config));
        let mut ttl = agent(now);
        ttl.status = AgentStatus::Active;
        assert!(needs_reactivation(&ttl, &config));
        ttl.expires_at = None;
        config.agent_max_lifetime = 60;
        assert!(needs_reactivation(&ttl, &config));
    }

    #[derive(Default)]
    struct Recorder(Mutex<Vec<AgentAuthEvent>>);

    #[async_trait]
    impl AgentEventCallback for Recorder {
        async fn call(&self, event: AgentAuthEvent) -> Result<(), String> {
            self.0.lock().unwrap().push(event);
            Ok(())
        }
    }

    #[tokio::test]
    async fn transparent_event_has_system_actor_and_marker() {
        let recorder = Arc::new(Recorder::default());
        let config = AgentAuthConfig {
            on_event: Some(recorder.clone()),
            ..AgentAuthConfig::default()
        };
        let (state, _) = state(config);
        let agent = agent(Utc::now());
        emit_transparent_reactivation(&state, &agent);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while recorder.0.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let event = serde_json::to_value(&recorder.0.lock().unwrap()[0]).unwrap();
        assert_eq!(event["type"], "agent.reactivated");
        assert_eq!(event["actorType"], "system");
        assert_eq!(event["metadata"]["transparent"], true);
    }
}
