use super::{
    error::{FlowError, Result, response},
    model::RevokeCapabilityBody,
    support::{emit, scoped_auth, validate_nonempty},
};
use crate::{
    AgentAuthAuditEventType, AgentAuthEventFields, AgentCapabilityTransitionOutcome,
    AgentCapabilityTransitionPlan, AgentGrantStatus, AgentRevokeCapabilitiesTransition,
    AuthService,
    agent_auth::axum::{AgentAuthState, auth::ScopedAgentAuthentication, input::AgentJson},
};
use axum::{
    Extension,
    extract::OriginalUri,
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde_json::{Map, json};
use std::sync::Arc;

pub(in crate::agent_auth::axum) async fn revoke_capability(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    AgentJson(body): AgentJson<RevokeCapabilityBody>,
) -> Response {
    let serialized = serde_json::to_string(&body).expect("request serializes");
    let scoped = match scoped_auth(
        &service,
        &state,
        &headers,
        &uri,
        &method,
        "/agent/revoke-capability",
        Some(&serialized),
    )
    .await
    {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let user = crate::axum::http::current_session(&service, &headers).await;
    if matches!(scoped, ScopedAgentAuthentication::NotApplicable) && user.is_none() {
        return FlowError::code(
            StatusCode::UNAUTHORIZED,
            crate::AgentAuthErrorCode::UnauthorizedSession,
        )
        .into_response();
    }
    response(run(&state, scoped, user.map(|session| session.user.id), body).await)
}

async fn run(
    state: &AgentAuthState,
    scoped: ScopedAgentAuthentication,
    user_id: Option<uuid::Uuid>,
    body: RevokeCapabilityBody,
) -> Result<serde_json::Value> {
    validate_nonempty(&body.capabilities)?;
    let (agent, host, grants) = load_authorized(state, &scoped, user_id, &body.agent_id).await?;
    let expected_grants = grants.clone();
    let (changed, revoked, grant_ids) = revoke_matching(grants, &body.capabilities);
    apply(state, &agent, host, expected_grants, changed).await?;
    emit_revoked(state, &scoped, user_id, &agent, &revoked, &grant_ids).await;
    Ok(json!({"agent_id": agent.id, "revoked": revoked, "grant_ids": grant_ids}))
}

async fn load_authorized(
    state: &AgentAuthState,
    scoped: &ScopedAgentAuthentication,
    user_id: Option<uuid::Uuid>,
    agent_id: &str,
) -> Result<(
    crate::AgentIdentity,
    Option<crate::AgentHost>,
    Vec<crate::AgentCapabilityGrant>,
)> {
    let agent = state.store.find_agent(agent_id).await?.ok_or_else(|| {
        FlowError::code(
            StatusCode::NOT_FOUND,
            crate::AgentAuthErrorCode::AgentNotFound,
        )
    })?;
    if agent.status == crate::AgentStatus::Revoked {
        return Err(FlowError::code(
            StatusCode::FORBIDDEN,
            crate::AgentAuthErrorCode::AgentRevoked,
        ));
    }
    let host = state.store.find_host(&agent.host_id).await?;
    let authorized = match scoped {
        ScopedAgentAuthentication::Agent(session) => session.agent.id == agent.id,
        ScopedAgentAuthentication::Host(session) => session.host.id == agent.host_id,
        ScopedAgentAuthentication::NotApplicable => match user_id {
            Some(user) if agent.user_id == Some(user) => true,
            Some(user) => host.as_ref().is_some_and(|host| host.user_id == Some(user)),
            None => false,
        },
    };
    if !authorized {
        return Err(FlowError::code(
            StatusCode::FORBIDDEN,
            crate::AgentAuthErrorCode::Unauthorized,
        ));
    }
    let grants = state.store.list_grants(&agent.id).await?;
    Ok((agent, host, grants))
}

fn revoke_matching(
    mut grants: Vec<crate::AgentCapabilityGrant>,
    capabilities: &[String],
) -> (Vec<crate::AgentCapabilityGrant>, Vec<String>, Vec<String>) {
    let now = Utc::now();
    let mut revoked = Vec::new();
    let mut grant_ids = Vec::new();
    for capability in capabilities {
        let mut flipped = false;
        for grant in grants.iter_mut().filter(|grant| {
            grant.capability == *capability && grant.status != AgentGrantStatus::Revoked
        }) {
            grant.status = AgentGrantStatus::Revoked;
            grant.updated_at = now;
            grant_ids.push(grant.id.clone());
            flipped = true;
        }
        if flipped {
            revoked.push(capability.clone());
        }
    }
    let changed = grants
        .into_iter()
        .filter(|grant| grant_ids.contains(&grant.id))
        .collect();
    (changed, revoked, grant_ids)
}

async fn apply(
    state: &AgentAuthState,
    agent: &crate::AgentIdentity,
    host: Option<crate::AgentHost>,
    expected_grants: Vec<crate::AgentCapabilityGrant>,
    changed: Vec<crate::AgentCapabilityGrant>,
) -> Result<()> {
    let approvals = state
        .store
        .list_pending_approvals_for_agent(&agent.id)
        .await?;
    let outcome = state
        .store
        .revoke_capabilities_atomic(AgentRevokeCapabilitiesTransition(
            AgentCapabilityTransitionPlan {
                expected_agent: agent.clone(),
                expected_host: host,
                expected_grants,
                expected_approvals: approvals,
                expected_related_agents: None,
                expected_related_grants: None,
                agent_update: None,
                host_update: None,
                related_agents_to_update: Vec::new(),
                related_grants_to_update: Vec::new(),
                grants_to_create: Vec::new(),
                grants_to_update: changed,
                grant_ids_to_delete: Vec::new(),
                approval_to_create: None,
                approvals_to_update: Vec::new(),
            },
        ))
        .await?;
    if !matches!(outcome, AgentCapabilityTransitionOutcome::Applied(_)) {
        return Err(FlowError::internal());
    }
    Ok(())
}

async fn emit_revoked(
    state: &AgentAuthState,
    scoped: &ScopedAgentAuthentication,
    user_id: Option<uuid::Uuid>,
    agent: &crate::AgentIdentity,
    revoked: &[String],
    grant_ids: &[String],
) {
    if !revoked.is_empty() {
        let actor_id = user_id.map(|id| id.to_string()).or_else(|| match &scoped {
            ScopedAgentAuthentication::Agent(session) => Some(session.user.id.clone()),
            ScopedAgentAuthentication::Host(session) => {
                session.host.user_id.map(|id| id.to_string())
            }
            ScopedAgentAuthentication::NotApplicable => None,
        });
        emit(
            &state.config,
            AgentAuthAuditEventType::CapabilityRevoked,
            AgentAuthEventFields {
                actor_id,
                agent_id: Some(agent.id.clone()),
                host_id: Some(agent.host_id.clone()),
                metadata: Some(Map::from_iter([
                    ("capabilities".into(), json!(revoked)),
                    ("grantIds".into(), json!(grant_ids)),
                ])),
                ..AgentAuthEventFields::default()
            },
        )
        .await;
    }
}
