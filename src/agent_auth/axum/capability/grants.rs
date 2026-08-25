use super::super::AgentAuthState;
use crate::{
    AgentCapabilityGrant, AgentGrantStatus, AgentSession, AgentStoreCreateOutcome,
    agent_auth::policy::{has_capability, validate_constraints},
};
use chrono::{Duration, Utc};
use serde_json::{Map, Value};
use uuid::Uuid;

pub(super) async fn active_for(
    state: &AgentAuthState,
    agent_id: &str,
    capability: &str,
) -> Result<Vec<AgentCapabilityGrant>, crate::AuthError> {
    let now = Utc::now();
    Ok(state
        .store
        .list_grants(agent_id)
        .await?
        .into_iter()
        .filter(|grant| {
            grant.capability == capability
                && grant.status == AgentGrantStatus::Active
                && grant.expires_at.is_none_or(|expires_at| expires_at > now)
        })
        .collect())
}

pub(super) fn matching(
    grants: &[AgentCapabilityGrant],
    arguments: Option<&Map<String, Value>>,
) -> Option<AgentCapabilityGrant> {
    grants
        .iter()
        .find(|grant| {
            grant
                .constraints
                .as_ref()
                .is_none_or(|constraints| validate_constraints(constraints, arguments).valid)
        })
        .cloned()
}

pub(super) async fn auto_grant(
    state: &AgentAuthState,
    session: &AgentSession,
    capability: &str,
) -> Result<Option<AgentCapabilityGrant>, crate::AuthError> {
    let Some(host) = state.store.find_host(&session.agent.host_id).await? else {
        return Ok(None);
    };
    if host.status != crate::AgentHostStatus::Active
        || !has_capability(&host.default_capabilities, capability)
    {
        return Ok(None);
    }
    let existing: Vec<_> = state
        .store
        .list_grants(&session.agent.id)
        .await?
        .into_iter()
        .filter(|grant| grant.capability == capability)
        .collect();
    if existing.iter().any(|grant| {
        matches!(
            grant.status,
            AgentGrantStatus::Revoked | AgentGrantStatus::Denied
        )
    }) {
        return Ok(None);
    }
    let now = Utc::now();
    let ttl = if let Some(resolver) = &state.config.resolve_grant_ttl {
        resolver
            .resolve(crate::AgentGrantTtlContext {
                capability: capability.to_owned(),
                agent_id: session.agent.id.clone(),
                host_id: Some(session.agent.host_id.clone()),
                user_id: session.host.as_ref().and_then(|host| host.user_id),
            })
            .await
    } else {
        None
    }
    .or_else(|| {
        state
            .config
            .capabilities
            .iter()
            .find(|definition| definition.name == capability)
            .and_then(|definition| definition.grant_ttl)
    });
    let grant = AgentCapabilityGrant {
        id: Uuid::new_v4().to_string(),
        agent_id: session.agent.id.clone(),
        capability: capability.to_owned(),
        constraints: None,
        denied_by: None,
        granted_by: host.user_id,
        expires_at: ttl
            .filter(|ttl| *ttl > 0)
            .and_then(|ttl| Duration::try_seconds(ttl as i64))
            .map(|ttl| now + ttl),
        status: AgentGrantStatus::Active,
        reason: Some("auto_granted_from_host_budget".into()),
        created_at: now,
        updated_at: now,
    };
    match state.store.create_grant(grant.clone()).await? {
        AgentStoreCreateOutcome::Created(grant) => {
            emit_auto_grant(state, session, capability).await;
            Ok(Some(grant))
        }
        AgentStoreCreateOutcome::UniqueConflict => Ok(existing.into_iter().find(|grant| {
            grant.status == AgentGrantStatus::Active
                && grant.expires_at.is_none_or(|expires_at| expires_at > now)
        })),
    }
}

async fn emit_auto_grant(state: &AgentAuthState, session: &AgentSession, capability: &str) {
    let event = crate::AgentAuthEvent::Audit(Box::new(crate::AgentAuthAuditEvent {
        r#type: crate::AgentAuthAuditEventType::CapabilityGranted,
        fields: crate::AgentAuthEventFields {
            actor_type: Some("system".into()),
            agent_id: Some(session.agent.id.clone()),
            host_id: Some(session.agent.host_id.clone()),
            metadata: Some(Map::from_iter([
                (
                    "capabilities".into(),
                    Value::Array(vec![Value::String(capability.into())]),
                ),
                ("auto".into(), Value::Bool(true)),
            ])),
            ..crate::AgentAuthEventFields::default()
        },
    }));
    super::super::events::emit(&state.config, event);
}
