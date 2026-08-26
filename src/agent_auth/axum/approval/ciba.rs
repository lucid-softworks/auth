use super::{
    error::{FlowError, Result, response},
    model::CibaAuthorizeBody,
    support::{APPROVAL_EXPIRES_IN, APPROVAL_INTERVAL, emit, sanitize_display, scoped_auth},
};
use crate::{
    AgentApprovalMethod, AgentApprovalRequest, AgentApprovalStatus, AgentAuthAuditEventType,
    AgentAuthEventFields, AgentGrantStatus, AgentStoreCreateOutcome, AuthService,
    agent_auth::axum::{AgentAuthState, auth::ScopedAgentAuthentication, input::AgentJson},
};
use axum::{
    Extension,
    extract::OriginalUri,
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use serde_json::{Map, Value, json};
use std::sync::Arc;
use uuid::Uuid;

pub(in crate::agent_auth::axum) async fn authorize(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    AgentJson(body): AgentJson<CibaAuthorizeBody>,
) -> Response {
    if !state
        .config
        .approval_methods
        .contains(&AgentApprovalMethod::Ciba)
        || body.login_hint.is_empty()
    {
        return FlowError::code(
            StatusCode::BAD_REQUEST,
            crate::AgentAuthErrorCode::InvalidRequest,
        )
        .into_response();
    }
    let serialized = serde_json::to_string(&body).expect("request serializes");
    let scoped = match scoped_auth(
        &service,
        &state,
        &headers,
        &uri,
        &method,
        "/agent/ciba/authorize",
        Some(&serialized),
    )
    .await
    {
        Ok(scoped) => scoped,
        Err(response) => return response,
    };
    let ScopedAgentAuthentication::Host(host) = scoped else {
        return FlowError::code(
            StatusCode::UNAUTHORIZED,
            crate::AgentAuthErrorCode::Unauthorized,
        )
        .into_response();
    };
    response(run_authorize(&service, &state, &host.host.id, body).await)
}

async fn run_authorize(
    service: &AuthService,
    state: &AgentAuthState,
    host_id: &str,
    body: CibaAuthorizeBody,
) -> Result<Value> {
    let user = service.auth_user_by_email(&body.login_hint).await?;
    let Some(user) = user else {
        // Preserve CIBA account-enumeration resistance with indistinguishable work and envelope.
        let _ = super::support::hash_token(&body.login_hint);
        return Ok(json!({
            "auth_req_id": Uuid::new_v4().to_string(),
            "expires_in": APPROVAL_EXPIRES_IN,
            "interval": APPROVAL_INTERVAL,
        }));
    };
    let now = Utc::now();
    let binding_message = sanitize_display(body.binding_message, 500);
    let approval = AgentApprovalRequest {
        id: Uuid::new_v4().to_string(),
        method: AgentApprovalMethod::Ciba,
        agent_id: body.agent_id.clone(),
        host_id: Some(host_id.to_owned()),
        user_id: Some(user.id.clone()),
        capabilities: body.capabilities.as_ref().map(|items| items.join(" ")),
        status: AgentApprovalStatus::Pending,
        user_code_hash: None,
        login_hint: Some(body.login_hint),
        binding_message: binding_message.clone(),
        client_notification_token: None,
        client_notification_endpoint: None,
        delivery_mode: Some("poll".into()),
        interval: APPROVAL_INTERVAL,
        last_polled_at: None,
        expires_at: now + Duration::seconds(APPROVAL_EXPIRES_IN),
        created_at: now,
        updated_at: now,
    };
    match state.store.create_approval(approval.clone()).await? {
        AgentStoreCreateOutcome::Created(_) => {}
        AgentStoreCreateOutcome::UniqueConflict => return Err(FlowError::internal()),
    }
    emit(
        &state.config,
        AgentAuthAuditEventType::ApprovalCreated,
        AgentAuthEventFields {
            actor_id: Some(user.id),
            host_id: Some(host_id.to_owned()),
            target_id: Some(approval.id.clone()),
            target_type: Some("approvalRequest".into()),
            metadata: Some(Map::from_iter([
                ("method".into(), json!("ciba")),
                ("capabilities".into(), json!(body.capabilities)),
                ("bindingMessage".into(), json!(binding_message)),
                ("agentId".into(), json!(body.agent_id)),
            ])),
            ..AgentAuthEventFields::default()
        },
    )
    .await;
    Ok(
        json!({"auth_req_id": approval.id, "expires_in": APPROVAL_EXPIRES_IN, "interval": APPROVAL_INTERVAL}),
    )
}

pub(in crate::agent_auth::axum) async fn pending(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = crate::axum::http::current_session(&service, &headers).await else {
        return FlowError::code(
            StatusCode::UNAUTHORIZED,
            crate::AgentAuthErrorCode::UnauthorizedSession,
        )
        .into_response();
    };
    response(run_pending(&state, &session.user.id).await)
}

async fn run_pending(state: &AgentAuthState, user_id: &str) -> Result<Value> {
    let now = Utc::now();
    let mut approvals = state.store.list_pending_approvals(user_id).await?;
    approvals.retain(|approval| approval.expires_at > now);
    approvals.sort_by_key(|approval| std::cmp::Reverse(approval.created_at));
    let mut requests = Vec::with_capacity(approvals.len());
    for approval in approvals {
        let (agent_name, constraints, reasons) = if let Some(agent_id) = &approval.agent_id {
            let name = state
                .store
                .find_agent(agent_id)
                .await?
                .map(|agent| agent.name);
            let grants = state.store.list_grants(agent_id).await?;
            let constraints = grants
                .iter()
                .filter(|grant| grant.status == AgentGrantStatus::Pending)
                .filter_map(|grant| {
                    grant
                        .constraints
                        .as_ref()
                        .map(|value| (grant.capability.clone(), json!(value)))
                })
                .collect::<Map<String, Value>>();
            let reasons = grants
                .iter()
                .filter(|grant| grant.status == AgentGrantStatus::Pending)
                .filter_map(|grant| {
                    grant
                        .reason
                        .as_ref()
                        .map(|value| (grant.capability.clone(), json!(value)))
                })
                .collect::<Map<String, Value>>();
            (
                name,
                (!constraints.is_empty()).then_some(constraints),
                (!reasons.is_empty()).then_some(reasons),
            )
        } else {
            (None, None, None)
        };
        requests.push(json!({
            "approval_id": approval.id,
            "method": approval.method.as_str(),
            "agent_id": approval.agent_id,
            "agent_name": agent_name,
            "binding_message": approval.binding_message,
            "capabilities": approval.capabilities.as_deref().unwrap_or_default().split_whitespace().collect::<Vec<_>>(),
            "capability_constraints": constraints,
            "capability_reasons": reasons,
            "expires_in": (approval.expires_at - now).num_seconds().max(0),
            "created_at": approval.created_at,
        }));
    }
    Ok(json!({"requests": requests}))
}
