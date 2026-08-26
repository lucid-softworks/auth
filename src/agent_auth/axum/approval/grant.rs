use super::{
    error::{FlowError, Result, response},
    model::GrantCapabilityBody,
    support::{
        emit, expires_at, normalize_requests, validate_capabilities, validate_nonempty,
        validate_positive,
    },
};
use crate::{
    AgentAuthAuditEventType, AgentAuthEventFields, AgentCapabilityGrant,
    AgentCapabilityTransitionOutcome, AgentCapabilityTransitionPlan,
    AgentGrantCapabilitiesTransition, AgentGrantStatus, AuthService,
    agent_auth::axum::{AgentAuthState, input::AgentJson},
};
use axum::{
    Extension,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use chrono::Utc;
use serde_json::{Map, json};
use std::sync::Arc;
use uuid::Uuid;

pub(in crate::agent_auth::axum) async fn grant_capability(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    AgentJson(body): AgentJson<GrantCapabilityBody>,
) -> Response {
    let Some(session) = crate::axum::http::current_session(&service, &headers).await else {
        return FlowError::code(
            StatusCode::UNAUTHORIZED,
            crate::AgentAuthErrorCode::UnauthorizedSession,
        )
        .into_response();
    };
    response(run(&state, &session.user.id, body).await)
}

async fn run(
    state: &AgentAuthState,
    user_id: &str,
    body: GrantCapabilityBody,
) -> Result<serde_json::Value> {
    validate_nonempty(&body.capabilities)?;
    validate_positive(body.ttl)?;
    let normalized = normalize_requests(&body.capabilities);
    validate_capabilities(
        &state.config,
        &normalized,
        crate::AgentAuthErrorCode::CapabilityBlocked,
    )
    .await?;
    let (agent, host, existing) = load_authorized(state, &body.agent_id, user_id).await?;
    let mutations = build_mutations(state, &agent, user_id, body.ttl, normalized, &existing).await;
    apply(
        state,
        &agent,
        host,
        existing,
        mutations.grants_to_create,
        mutations.grants_to_update,
    )
    .await?;
    emit_granted(state, user_id, &agent, &mutations.added).await;
    Ok(json!({
        "agent_id": agent.id,
        "grant_ids": mutations.grant_ids,
        "added": mutations.added
    }))
}

async fn load_authorized(
    state: &AgentAuthState,
    agent_id: &str,
    user_id: &str,
) -> Result<(
    crate::AgentIdentity,
    Option<crate::AgentHost>,
    Vec<AgentCapabilityGrant>,
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
    if agent
        .user_id
        .as_deref()
        .is_some_and(|owner| owner != user_id)
    {
        let owned_host = host
            .as_ref()
            .is_some_and(|host| host.user_id.as_deref() == Some(user_id));
        if !owned_host {
            return Err(FlowError::code(
                StatusCode::FORBIDDEN,
                crate::AgentAuthErrorCode::Unauthorized,
            ));
        }
    }
    let existing = state.store.list_grants(&agent.id).await?;
    Ok((agent, host, existing))
}

struct GrantMutations {
    grant_ids: Vec<String>,
    added: Vec<String>,
    grants_to_update: Vec<AgentCapabilityGrant>,
    grants_to_create: Vec<AgentCapabilityGrant>,
}

async fn build_mutations(
    state: &AgentAuthState,
    agent: &crate::AgentIdentity,
    user_id: &str,
    ttl: Option<f64>,
    normalized: Vec<(String, Option<crate::AgentCapabilityConstraints>)>,
    existing: &[AgentCapabilityGrant],
) -> GrantMutations {
    let now = Utc::now();
    let mut grant_ids = Vec::new();
    let mut added = Vec::new();
    let mut grants_to_update = Vec::new();
    let mut grants_to_create = Vec::new();
    for (capability, constraints) in normalized {
        if let Some(mut pending) = existing
            .iter()
            .find(|grant| {
                grant.capability == capability && grant.status == AgentGrantStatus::Pending
            })
            .cloned()
        {
            pending.status = AgentGrantStatus::Active;
            pending.granted_by = Some(user_id.to_owned());
            pending.expires_at = expires_at(&state.config, &capability, agent, ttl).await;
            pending.updated_at = now;
            if constraints.is_some() {
                pending.constraints = constraints;
            }
            grant_ids.push(pending.id.clone());
            grants_to_update.push(pending);
        } else if existing
            .iter()
            .any(|grant| grant.capability == capability && grant.status == AgentGrantStatus::Active)
        {
            continue;
        } else {
            let grant = AgentCapabilityGrant {
                id: Uuid::new_v4().to_string(),
                agent_id: agent.id.clone(),
                capability: capability.clone(),
                constraints,
                denied_by: None,
                granted_by: Some(user_id.to_owned()),
                expires_at: expires_at(&state.config, &capability, agent, ttl).await,
                status: AgentGrantStatus::Active,
                reason: None,
                created_at: now,
                updated_at: now,
            };
            grant_ids.push(grant.id.clone());
            grants_to_create.push(grant);
        }
        added.push(capability);
    }
    GrantMutations {
        grant_ids,
        added,
        grants_to_update,
        grants_to_create,
    }
}

async fn apply(
    state: &AgentAuthState,
    agent: &crate::AgentIdentity,
    host: Option<crate::AgentHost>,
    existing: Vec<AgentCapabilityGrant>,
    grants_to_create: Vec<AgentCapabilityGrant>,
    grants_to_update: Vec<AgentCapabilityGrant>,
) -> Result<()> {
    let approvals = state
        .store
        .list_pending_approvals_for_agent(&agent.id)
        .await?;
    let outcome = state
        .store
        .grant_capabilities_atomic(AgentGrantCapabilitiesTransition(
            AgentCapabilityTransitionPlan {
                expected_agent: agent.clone(),
                expected_host: host,
                expected_grants: existing,
                expected_approvals: approvals,
                expected_related_agents: None,
                expected_related_grants: None,
                agent_update: None,
                host_update: None,
                related_agents_to_update: Vec::new(),
                related_grants_to_update: Vec::new(),
                grants_to_create,
                grants_to_update,
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

async fn emit_granted(
    state: &AgentAuthState,
    user_id: &str,
    agent: &crate::AgentIdentity,
    added: &[String],
) {
    emit(
        &state.config,
        AgentAuthAuditEventType::CapabilityGranted,
        AgentAuthEventFields {
            actor_id: Some(user_id.to_owned()),
            agent_id: Some(agent.id.clone()),
            metadata: Some(Map::from_iter([("capabilities".into(), json!(added))])),
            ..AgentAuthEventFields::default()
        },
    )
    .await;
}

use axum::response::IntoResponse as _;
