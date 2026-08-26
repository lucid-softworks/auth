use super::{
    error::{FlowError, Result},
    model::RequestCapabilityBody,
    request::{apply_transition, create_grant, existing_pending_approval, requested_grants},
    support::{
        constraint_map, emit, expires_at, format_grants, normalize_requests, sanitize_display,
        validate_capabilities, validate_nonempty, validate_required_constraints,
    },
};
use crate::{
    AgentAuthAuditEventType, AgentAuthEventFields, AgentCapabilityConstraints,
    AgentCapabilityGrant, AgentGrantStatus, AgentMode, AuthService,
    agent_auth::{axum::AgentAuthState, policy},
};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub(super) async fn run(
    service: &AuthService,
    state: &AgentAuthState,
    origin: &str,
    session: crate::AgentSession,
    body: RequestCapabilityBody,
) -> Result<Value> {
    let request = Request::load(state, session, body).await?;
    let new_only = request.new_only();
    if new_only.is_empty() {
        resolve_existing(service, state, origin, request).await
    } else {
        resolve_new(service, state, origin, request, new_only).await
    }
}

struct Request {
    agent: crate::AgentIdentity,
    existing: Vec<AgentCapabilityGrant>,
    host: Option<crate::AgentHost>,
    approvals: Vec<crate::AgentApprovalRequest>,
    capability_ids: Vec<String>,
    constraints: BTreeMap<String, Option<AgentCapabilityConstraints>>,
    owner_id: Option<String>,
    reason: Option<String>,
    binding_message: Option<String>,
    preferred_method: Option<String>,
    login_hint: Option<String>,
    now: DateTime<Utc>,
}

impl Request {
    async fn load(
        state: &AgentAuthState,
        session: crate::AgentSession,
        body: RequestCapabilityBody,
    ) -> Result<Self> {
        validate_nonempty(&body.capabilities)?;
        let normalized = normalize_requests(&body.capabilities);
        validate_required_constraints(&state.config, &normalized)?;
        validate_capabilities(
            &state.config,
            &normalized,
            crate::AgentAuthErrorCode::InvalidCapabilities,
        )
        .await?;
        let agent = state
            .store
            .find_agent(&session.agent.id)
            .await?
            .ok_or_else(|| {
                FlowError::code(
                    StatusCode::NOT_FOUND,
                    crate::AgentAuthErrorCode::AgentNotFound,
                )
            })?;
        Ok(Self {
            existing: state.store.list_grants(&agent.id).await?,
            host: state.store.find_host(&agent.host_id).await?,
            approvals: state
                .store
                .list_pending_approvals_for_agent(&agent.id)
                .await?,
            capability_ids: normalized.iter().map(|(name, _)| name.clone()).collect(),
            constraints: constraint_map(&normalized),
            owner_id: session.host.as_ref().and_then(|host| host.user_id.clone()),
            reason: sanitize_display(body.reason, 500),
            binding_message: sanitize_display(body.binding_message, 500),
            preferred_method: body.preferred_method,
            login_hint: body.login_hint,
            now: Utc::now(),
            agent,
        })
    }

    fn covered(&self, grant: &AgentCapabilityGrant, capability: &str) -> bool {
        grant.capability == capability
            && policy::constraints_cover(
                grant.constraints.as_ref(),
                self.constraints.get(capability).and_then(Option::as_ref),
            )
    }

    fn active(&self, capability: &str) -> bool {
        self.existing.iter().any(|grant| {
            grant.status == AgentGrantStatus::Active
                && grant.expires_at.is_none_or(|expiry| expiry > self.now)
                && self.covered(grant, capability)
        })
    }

    fn pending(&self, capability: &str) -> bool {
        self.existing.iter().any(|grant| {
            grant.status == AgentGrantStatus::Pending
                && (grant.granted_by.is_none() || grant.granted_by == self.owner_id)
                && self.covered(grant, capability)
        })
    }

    fn new_only(&self) -> Vec<String> {
        self.capability_ids
            .iter()
            .filter(|name| !self.active(name) && !self.pending(name))
            .cloned()
            .collect()
    }
}

async fn resolve_existing(
    service: &AuthService,
    state: &AgentAuthState,
    origin: &str,
    request: Request,
) -> Result<Value> {
    if request
        .capability_ids
        .iter()
        .all(|name| request.active(name))
    {
        return Err(FlowError::code(
            StatusCode::CONFLICT,
            crate::AgentAuthErrorCode::AlreadyGranted,
        ));
    }
    let requested = requested_grants(&request.existing, &request.capability_ids);
    if let Some(approval) = existing_pending_approval(&request.approvals, request.now) {
        return Ok(json!({
            "agent_id": request.agent.id, "status": "pending",
            "agent_capability_grants": format_grants(&requested, &state.config),
            "approval": {"method": approval.method.as_str(), "expires_in": (approval.expires_at - request.now).num_seconds(), "interval": approval.interval}
        }));
    }
    let pending = request
        .capability_ids
        .iter()
        .filter(|name| request.pending(name))
        .cloned()
        .collect();
    let approval = build_approval(service, state, origin, &request, pending).await?;
    apply_transition(
        state,
        &request.agent,
        request.host,
        request.existing,
        request.approvals,
        Vec::new(),
        Some(approval.record),
    )
    .await?;
    Ok(json!({
        "agent_id": request.agent.id, "status": "pending",
        "agent_capability_grants": format_grants(&requested, &state.config),
        "approval": approval.response
    }))
}

async fn resolve_new(
    service: &AuthService,
    state: &AgentAuthState,
    origin: &str,
    request: Request,
    new_only: Vec<String>,
) -> Result<Value> {
    let (auto, mut needs) = classify(&request, new_only);
    if request.agent.mode == AgentMode::Autonomous
        && request
            .host
            .as_ref()
            .and_then(|host| host.user_id.as_ref())
            .is_none()
    {
        needs.clear();
    }
    let new_grants = automatic_grants(state, &request, &auto).await;
    if needs.is_empty() {
        resolve_automatic(state, request, auto, new_grants).await
    } else {
        resolve_pending(service, state, origin, request, auto, needs, new_grants).await
    }
}

fn classify(request: &Request, new_only: Vec<String>) -> (Vec<String>, Vec<String>) {
    let host_active = request
        .host
        .as_ref()
        .is_some_and(|host| host.status == crate::AgentHostStatus::Active);
    let host_budget = request
        .host
        .as_ref()
        .map(|host| host.default_capabilities.as_slice())
        .unwrap_or_default();
    new_only.into_iter().partition(|name| {
        let denied = request.existing.iter().any(|grant| {
            grant.capability == *name
                && matches!(
                    grant.status,
                    AgentGrantStatus::Revoked | AgentGrantStatus::Denied
                )
        });
        host_active && policy::has_capability(host_budget, name) && !denied
    })
}

async fn automatic_grants(
    state: &AgentAuthState,
    request: &Request,
    auto: &[String],
) -> Vec<AgentCapabilityGrant> {
    let mut grants = Vec::new();
    for name in auto {
        grants.push(create_grant(
            &request.agent,
            super::request::GrantInput {
                capability: name,
                constraints: request.constraints.get(name).cloned().flatten(),
                granted_by: request.owner_id.clone(),
                status: AgentGrantStatus::Active,
                reason: request.reason.clone(),
                expires_at: expires_at(&state.config, name, &request.agent, None).await,
                now: request.now,
            },
        ));
    }
    grants
}

async fn resolve_automatic(
    state: &AgentAuthState,
    request: Request,
    auto: Vec<String>,
    grants: Vec<AgentCapabilityGrant>,
) -> Result<Value> {
    if !auto.is_empty() {
        emit(
            &state.config,
            AgentAuthAuditEventType::CapabilityGranted,
            AgentAuthEventFields {
                actor_type: Some("system".into()),
                agent_id: Some(request.agent.id.clone()),
                host_id: Some(request.agent.host_id.clone()),
                metadata: Some(Map::from_iter([
                    ("capabilities".into(), json!(auto)),
                    ("auto".into(), json!(true)),
                ])),
                ..AgentAuthEventFields::default()
            },
        )
        .await;
    }
    let result = apply_transition(
        state,
        &request.agent,
        request.host,
        request.existing,
        request.approvals,
        grants,
        None,
    )
    .await?;
    Ok(json!({
        "agent_id": request.agent.id, "status": "active",
        "agent_capability_grants": format_grants(&requested_grants(&result.grants, &request.capability_ids), &state.config)
    }))
}

async fn resolve_pending(
    service: &AuthService,
    state: &AgentAuthState,
    origin: &str,
    request: Request,
    auto: Vec<String>,
    needs: Vec<String>,
    mut grants: Vec<AgentCapabilityGrant>,
) -> Result<Value> {
    grants.extend(needs.iter().map(|name| {
        create_grant(
            &request.agent,
            super::request::GrantInput {
                capability: name,
                constraints: request.constraints.get(name).cloned().flatten(),
                granted_by: request.owner_id.clone(),
                status: AgentGrantStatus::Pending,
                reason: request.reason.clone(),
                expires_at: None,
                now: request.now,
            },
        )
    }));
    let approval = build_approval(service, state, origin, &request, needs.clone()).await?;
    let result = apply_transition(
        state,
        &request.agent,
        request.host,
        request.existing,
        request.approvals,
        grants,
        Some(approval.record),
    )
    .await?;
    emit_requested(
        state,
        request.owner_id.clone(),
        &request.agent,
        request.reason.as_ref(),
        &auto,
        &needs,
    )
    .await;
    Ok(json!({
        "agent_id": request.agent.id, "status": "pending",
        "agent_capability_grants": format_grants(&requested_grants(&result.grants, &request.capability_ids), &state.config),
        "approval": approval.response
    }))
}

async fn build_approval(
    service: &AuthService,
    state: &AgentAuthState,
    origin: &str,
    request: &Request,
    capabilities: Vec<String>,
) -> Result<super::request_approval::BuiltApproval> {
    super::request_approval::build(
        service,
        state,
        super::request_approval::BuildRequest {
            origin,
            agent: &request.agent,
            user_id: request.owner_id.clone(),
            capabilities,
            preferred: request.preferred_method.clone(),
            login_hint: request.login_hint.clone(),
            binding_message: request.binding_message.clone(),
        },
    )
    .await
}

async fn emit_requested(
    state: &AgentAuthState,
    owner_id: Option<String>,
    agent: &crate::AgentIdentity,
    reason: Option<&String>,
    auto: &[String],
    needs: &[String],
) {
    emit(
        &state.config,
        AgentAuthAuditEventType::CapabilityRequested,
        AgentAuthEventFields {
            actor_id: owner_id,
            actor_type: Some("agent".into()),
            agent_id: Some(agent.id.clone()),
            host_id: Some(agent.host_id.clone()),
            metadata: Some(Map::from_iter([
                ("autoApproved".into(), json!(auto)),
                ("pending".into(), json!(needs)),
                ("reason".into(), json!(reason)),
            ])),
            ..AgentAuthEventFields::default()
        },
    )
    .await;
}
