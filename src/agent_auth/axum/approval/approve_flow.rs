use super::{
    error::{FlowError, Result},
    model::{ApprovalAction, ApproveCapabilityBody},
    support::{emit, hash_token, normalize_user_code, validate_positive},
};
use crate::{
    AgentApprovalStatus, AgentAuthAuditEventType, AgentAuthEventFields, AgentCapabilityGrant,
    AgentGrantStatus, AgentMode, AgentStatus, AuthService,
    agent_auth::{axum::AgentAuthState, policy},
};
use axum::http::{HeaderMap, StatusCode};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use std::collections::HashSet;

pub(super) async fn run(
    service: &AuthService,
    state: &AgentAuthState,
    session: crate::SessionWithUser,
    body: ApproveCapabilityBody,
    headers: &HeaderMap,
) -> Result<Value> {
    let mut approval = Approval::load(state, &session, &body).await?;
    if approval.is_claim {
        return super::claim::run(
            state,
            &session,
            super::claim::ClaimRequest {
                agent: &mut approval.agent,
                grants: approval.grants,
                host: approval.host,
                approvals: approval.approvals,
                approve: matches!(body.action, ApprovalAction::Approve),
                reason: body.reason,
            },
        )
        .await;
    }
    if approval.pending.is_empty() && !approval.agent_pending {
        return Err(FlowError::code(
            StatusCode::PRECONDITION_FAILED,
            crate::AgentAuthErrorCode::CapabilityRequestAlreadyResolved,
        ));
    }
    if matches!(body.action, ApprovalAction::Deny) {
        deny(state, &session, approval, body.reason).await
    } else {
        approve(service, state, &session, approval, body, headers).await
    }
}

pub(super) struct Approval {
    pub(super) user_id: uuid::Uuid,
    pub(super) agent_id: String,
    pub(super) agent: crate::AgentIdentity,
    pub(super) expected_agent: crate::AgentIdentity,
    pub(super) host: Option<crate::AgentHost>,
    pub(super) approvals: Vec<crate::AgentApprovalRequest>,
    pub(super) grants: Vec<AgentCapabilityGrant>,
    pub(super) pending: Vec<AgentCapabilityGrant>,
    pub(super) agent_pending: bool,
    pub(super) is_claim: bool,
    pub(super) now: DateTime<Utc>,
}

impl Approval {
    async fn load(
        state: &AgentAuthState,
        session: &crate::SessionWithUser,
        body: &ApproveCapabilityBody,
    ) -> Result<Self> {
        validate_positive(body.ttl)?;
        let (agent_id, selected) = identify(state, body).await?;
        let agent = state.store.find_agent(&agent_id).await?.ok_or_else(|| {
            FlowError::code(
                StatusCode::NOT_FOUND,
                crate::AgentAuthErrorCode::AgentNotFound,
            )
        })?;
        let is_claim = agent.mode == AgentMode::Autonomous && agent.status == AgentStatus::Active;
        if !is_claim && agent.user_id.is_some_and(|owner| owner != session.user.id) {
            return Err(FlowError::code(
                StatusCode::FORBIDDEN,
                crate::AgentAuthErrorCode::CapabilityRequestOwnerMismatch,
            ));
        }
        let approvals = state
            .store
            .list_pending_approvals_for_agent(&agent_id)
            .await?;
        validate_device(body, selected, &approvals)?;
        let grants = state.store.list_grants(&agent_id).await?;
        let pending = grants
            .iter()
            .filter(|grant| grant.status == AgentGrantStatus::Pending)
            .cloned()
            .collect();
        Ok(Self {
            user_id: session.user.id,
            agent_id,
            expected_agent: agent.clone(),
            host: state.store.find_host(&agent.host_id).await?,
            approvals,
            grants,
            pending,
            agent_pending: agent.status == AgentStatus::Pending,
            is_claim,
            agent,
            now: Utc::now(),
        })
    }
}

async fn identify(
    state: &AgentAuthState,
    body: &ApproveCapabilityBody,
) -> Result<(String, Option<crate::AgentApprovalRequest>)> {
    if let Some(approval_id) = &body.approval_id {
        let approval = state
            .store
            .find_approval(approval_id)
            .await?
            .filter(|approval| approval.agent_id.is_some())
            .ok_or_else(|| {
                FlowError::code(
                    StatusCode::NOT_FOUND,
                    crate::AgentAuthErrorCode::CapabilityRequestNotFound,
                )
            })?;
        return Ok((approval.agent_id.clone().expect("filtered"), Some(approval)));
    }
    body.agent_id.clone().map(|id| (id, None)).ok_or_else(|| {
        FlowError::message(
            StatusCode::BAD_REQUEST,
            crate::AgentAuthErrorCode::InvalidRequest,
            "Either agent_id or approval_id is required.",
        )
    })
}

fn validate_device(
    body: &ApproveCapabilityBody,
    selected: Option<crate::AgentApprovalRequest>,
    pending: &[crate::AgentApprovalRequest],
) -> Result<()> {
    let now = Utc::now();
    let approvals = super::resolution::device_approvals(selected, pending);
    if approvals.iter().any(|approval| approval.expires_at < now) {
        return Err(FlowError::code(
            StatusCode::FORBIDDEN,
            crate::AgentAuthErrorCode::ApprovalExpired,
        ));
    }
    if !matches!(body.action, ApprovalAction::Approve)
        || !approvals
            .iter()
            .any(|approval| approval.user_code_hash.is_some())
    {
        return Ok(());
    }
    let code = body.user_code.as_deref().ok_or_else(|| {
        FlowError::code(
            StatusCode::BAD_REQUEST,
            crate::AgentAuthErrorCode::InvalidUserCode,
        )
    })?;
    let submitted = hash_token(&normalize_user_code(code));
    if approvals
        .iter()
        .any(|approval| approval.user_code_hash.as_deref() == Some(&submitted))
    {
        Ok(())
    } else {
        Err(FlowError::code(
            StatusCode::FORBIDDEN,
            crate::AgentAuthErrorCode::InvalidUserCode,
        ))
    }
}

async fn deny(
    state: &AgentAuthState,
    session: &crate::SessionWithUser,
    mut approval: Approval,
    reason: Option<String>,
) -> Result<Value> {
    let grant_updates = approval
        .pending
        .iter()
        .cloned()
        .map(|mut grant| {
            grant.status = AgentGrantStatus::Denied;
            grant.updated_at = approval.now;
            grant
        })
        .collect();
    if approval.agent_pending {
        approval.agent.status = AgentStatus::Rejected;
        approval.agent.user_id = Some(session.user.id);
    }
    if let Some(reason) = &reason {
        approval
            .agent
            .metadata
            .get_or_insert_with(Map::new)
            .insert("denyReason".into(), json!(reason));
    }
    let update_agent = approval.agent_pending || reason.is_some();
    if update_agent {
        approval.agent.updated_at = approval.now;
    }
    let updates = super::resolution::resolved_approvals(
        &approval.approvals,
        AgentApprovalStatus::Denied,
        approval.now,
    );
    super::resolution::apply_resolution(
        state,
        &approval.expected_agent,
        approval.host.clone(),
        approval.grants.clone(),
        approval.approvals.clone(),
        update_agent.then_some(approval.agent.clone()),
        None,
        grant_updates,
        Vec::new(),
        updates,
    )
    .await?;
    after_denial(state, session, &approval, reason).await;
    Ok(json!({"status": "denied"}))
}

async fn after_denial(
    state: &AgentAuthState,
    session: &crate::SessionWithUser,
    approval: &Approval,
    reason: Option<String>,
) {
    super::notifications::deliver(
        &approval.approvals,
        json!({
            "agent_id": approval.agent_id, "status": "denied", "error": "access_denied",
            "message": reason.as_ref().map(|reason| format!("User denied the authorization request: {reason}")).unwrap_or_else(|| "User denied the authorization request.".into())
        }),
    );
    let capabilities = approval
        .grants
        .iter()
        .filter(|grant| grant.status == AgentGrantStatus::Pending)
        .map(|grant| &grant.capability)
        .collect::<Vec<_>>();
    emit(
        &state.config,
        AgentAuthAuditEventType::CapabilityDenied,
        AgentAuthEventFields {
            actor_id: Some(session.user.id.to_string()),
            agent_id: Some(approval.agent_id.clone()),
            metadata: Some(Map::from_iter([
                ("capabilities".into(), json!(capabilities)),
                ("reason".into(), json!(reason)),
            ])),
            ..AgentAuthEventFields::default()
        },
    )
    .await;
}

async fn approve(
    service: &AuthService,
    state: &AgentAuthState,
    session: &crate::SessionWithUser,
    mut approval: Approval,
    body: ApproveCapabilityBody,
    headers: &HeaderMap,
) -> Result<Value> {
    let approved = body
        .capabilities
        .clone()
        .map(HashSet::from_iter)
        .unwrap_or_else(|| {
            approval
                .pending
                .iter()
                .map(|grant| grant.capability.clone())
                .collect()
        });
    let capabilities = approved.iter().cloned().collect::<Vec<_>>();
    validate_approval(
        service,
        state,
        session,
        &approval,
        &body,
        headers,
        &capabilities,
    )
    .await?;
    let mutations =
        super::approve_mutation::build_mutations(state, session, &approval, approved, body.ttl)
            .await;
    let resolution = if !mutations.added.is_empty() || approval.agent_pending {
        AgentApprovalStatus::Approved
    } else {
        AgentApprovalStatus::Denied
    };
    let updates =
        super::resolution::resolved_approvals(&approval.approvals, resolution, approval.now);
    let activation = super::approve_mutation::activate(state, session, &mut approval).await?;
    super::approve_mutation::apply_approval(state, approval, mutations, updates, activation).await
}

async fn validate_approval(
    service: &AuthService,
    state: &AgentAuthState,
    session: &crate::SessionWithUser,
    approval: &Approval,
    body: &ApproveCapabilityBody,
    headers: &HeaderMap,
    capabilities: &[String],
) -> Result<()> {
    let fresh_window = match &state.config.resolve_fresh_session_window {
        Some(resolver) => {
            resolver
                .resolve(crate::AgentFreshSessionWindowContext {
                    endpoint: endpoint(),
                    capabilities: capabilities.to_vec(),
                })
                .await
        }
        None => state.config.fresh_session_window,
    };
    if fresh_window > 0 {
        let age = (approval.now - session.session.created_at)
            .num_seconds()
            .max(0) as u64;
        if age > fresh_window {
            return Err(FlowError::fresh_session(fresh_window, age));
        }
    }
    if state.config.proof_of_presence.enabled
        && super::presence::required(
            state,
            &approval.agent,
            approval.agent_pending,
            !approval.pending.is_empty(),
            capabilities,
        )
        .await?
    {
        super::presence::verify(service, state, session, &approval.agent_id, body, headers).await?;
    }
    let blocked =
        policy::find_blocked_capabilities(capabilities, &state.config.blocked_capabilities);
    if blocked.is_empty() {
        Ok(())
    } else {
        Err(FlowError::message(
            StatusCode::BAD_REQUEST,
            crate::AgentAuthErrorCode::CapabilityBlocked,
            format!("Blocked capabilities: {}", blocked.join(", ")),
        ))
    }
}

fn endpoint() -> crate::AgentEndpointContext {
    crate::AgentEndpointContext {
        method: "POST".into(),
        path: "/agent/approve-capability".into(),
        ..crate::AgentEndpointContext::default()
    }
}
