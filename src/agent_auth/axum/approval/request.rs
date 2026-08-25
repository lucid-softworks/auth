use super::{
    error::{FlowError, Result, response},
    model::RequestCapabilityBody,
    support::scoped_auth,
};
use crate::{
    AgentApprovalRequest, AgentCapabilityGrant, AgentCapabilityTransitionOutcome,
    AgentCapabilityTransitionPlan, AgentGrantStatus, AgentRequestCapabilitiesTransition,
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
use serde_json::Value;
use std::{collections::HashSet, sync::Arc};
use uuid::Uuid;

pub(in crate::agent_auth::axum) async fn request_capability(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    AgentJson(body): AgentJson<RequestCapabilityBody>,
) -> Response {
    let serialized = serde_json::to_string(&body).expect("request serializes");
    let scoped = match scoped_auth(
        &service,
        &state,
        &headers,
        &uri,
        &method,
        "/agent/request-capability",
        Some(&serialized),
    )
    .await
    {
        Ok(scoped) => scoped,
        Err(response) => return response,
    };
    let ScopedAgentAuthentication::Agent(session) = scoped else {
        return FlowError::code(
            StatusCode::UNAUTHORIZED,
            crate::AgentAuthErrorCode::UnauthorizedSession,
        )
        .into_response();
    };
    let base_url = super::super::issuer(&service, &headers);
    let origin = url::Url::parse(&base_url)
        .ok()
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_default();
    response(run(&service, &state, &origin, *session, body).await)
}

async fn run(
    service: &AuthService,
    state: &AgentAuthState,
    origin: &str,
    session: crate::AgentSession,
    body: RequestCapabilityBody,
) -> Result<Value> {
    super::request_flow::run(service, state, origin, session, body).await
}

pub(super) struct GrantInput<'a> {
    pub(super) capability: &'a str,
    pub(super) constraints: Option<crate::AgentCapabilityConstraints>,
    pub(super) granted_by: Option<Uuid>,
    pub(super) status: AgentGrantStatus,
    pub(super) reason: Option<String>,
    pub(super) expires_at: Option<chrono::DateTime<Utc>>,
    pub(super) now: chrono::DateTime<Utc>,
}

pub(super) fn create_grant(
    agent: &crate::AgentIdentity,
    input: GrantInput<'_>,
) -> AgentCapabilityGrant {
    AgentCapabilityGrant {
        id: Uuid::new_v4().to_string(),
        agent_id: agent.id.clone(),
        capability: input.capability.to_owned(),
        constraints: input.constraints,
        denied_by: None,
        granted_by: input.granted_by,
        expires_at: input.expires_at,
        status: input.status,
        reason: input.reason,
        created_at: input.now,
        updated_at: input.now,
    }
}

pub(super) fn requested_grants(
    grants: &[AgentCapabilityGrant],
    capabilities: &[String],
) -> Vec<AgentCapabilityGrant> {
    let requested = capabilities.iter().collect::<HashSet<_>>();
    grants
        .iter()
        .filter(|grant| requested.contains(&grant.capability))
        .cloned()
        .collect()
}

pub(super) fn existing_pending_approval(
    approvals: &[AgentApprovalRequest],
    now: chrono::DateTime<Utc>,
) -> Option<AgentApprovalRequest> {
    approvals
        .iter()
        .find(|approval| approval.expires_at > now)
        .cloned()
}

pub(super) async fn apply_transition(
    state: &AgentAuthState,
    agent: &crate::AgentIdentity,
    host: Option<crate::AgentHost>,
    expected_grants: Vec<AgentCapabilityGrant>,
    expected_approvals: Vec<AgentApprovalRequest>,
    grants_to_create: Vec<AgentCapabilityGrant>,
    approval_to_create: Option<AgentApprovalRequest>,
) -> Result<crate::AgentCapabilityTransitionResult> {
    let outcome = state
        .store
        .request_capabilities_atomic(AgentRequestCapabilitiesTransition(
            AgentCapabilityTransitionPlan {
                expected_agent: agent.clone(),
                expected_host: host,
                expected_grants,
                expected_approvals,
                expected_related_agents: None,
                expected_related_grants: None,
                agent_update: None,
                host_update: None,
                related_agents_to_update: Vec::new(),
                related_grants_to_update: Vec::new(),
                grants_to_create,
                grants_to_update: Vec::new(),
                grant_ids_to_delete: Vec::new(),
                approval_to_create,
                approvals_to_update: Vec::new(),
            },
        ))
        .await?;
    match outcome {
        AgentCapabilityTransitionOutcome::Applied(result) => Ok(*result),
        _ => Err(FlowError::internal()),
    }
}
