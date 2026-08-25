use super::{
    error::{FlowError, Result, response},
    model::DeviceCodeBody,
    support::{
        APPROVAL_EXPIRES_IN, APPROVAL_INTERVAL, generate_user_code, hash_token, scoped_auth,
    },
};
use crate::{
    AgentApprovalMethod, AgentApprovalRequest, AgentApprovalStatus, AgentStatus,
    AgentStoreCreateOutcome, AuthService,
    agent_auth::axum::{AgentAuthState, auth::ScopedAgentAuthentication, input::AgentJson},
};
use axum::{
    Extension,
    extract::OriginalUri,
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

pub(in crate::agent_auth::axum) async fn device_code(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    AgentJson(body): AgentJson<DeviceCodeBody>,
) -> Response {
    let serialized = serde_json::to_string(&body).expect("request serializes");
    let scoped = match scoped_auth(
        &service,
        &state,
        &headers,
        &uri,
        &method,
        "/agent/device/code",
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
            crate::AgentAuthErrorCode::UnauthorizedSession,
        )
        .into_response();
    };
    let base_url = super::super::issuer(&service, &headers);
    let origin = url::Url::parse(&base_url)
        .ok()
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_default();
    response(run(&state, &host.host.id, &origin, body).await)
}

async fn run(
    state: &AgentAuthState,
    host_id: &str,
    origin: &str,
    body: DeviceCodeBody,
) -> Result<Value> {
    let agent = pending_agent(state, &body.agent_id, host_id).await?;
    let user_code = generate_user_code();
    let approval = approval(&agent, &user_code);
    match state.store.create_approval(approval.clone()).await? {
        AgentStoreCreateOutcome::Created(_) => {}
        AgentStoreCreateOutcome::UniqueConflict => return Err(FlowError::internal()),
    }
    let page = verification_page(&state.config.device_authorization_page, origin);
    Ok(json!({
        "device_code": approval.id,
        "user_code": user_code,
        "verification_uri": page,
        "verification_uri_complete": format!("{page}?agent_id={}&code={user_code}", agent.id),
        "expires_in": APPROVAL_EXPIRES_IN,
        "interval": APPROVAL_INTERVAL,
    }))
}

async fn pending_agent(
    state: &AgentAuthState,
    agent_id: &str,
    host_id: &str,
) -> Result<crate::AgentIdentity> {
    let agent = state.store.find_agent(agent_id).await?.ok_or_else(|| {
        FlowError::code(
            StatusCode::NOT_FOUND,
            crate::AgentAuthErrorCode::AgentNotFound,
        )
    })?;
    if agent.host_id != host_id {
        return Err(FlowError::code(
            StatusCode::FORBIDDEN,
            crate::AgentAuthErrorCode::Unauthorized,
        ));
    }
    match agent.status {
        AgentStatus::Pending => {}
        AgentStatus::Active => {
            return Err(FlowError::message(
                StatusCode::BAD_REQUEST,
                crate::AgentAuthErrorCode::InvalidRequest,
                "Agent is already active. No approval needed.",
            ));
        }
        AgentStatus::Revoked => {
            return Err(FlowError::code(
                StatusCode::FORBIDDEN,
                crate::AgentAuthErrorCode::AgentRevoked,
            ));
        }
        AgentStatus::Rejected => {
            return Err(FlowError::code(
                StatusCode::FORBIDDEN,
                crate::AgentAuthErrorCode::AgentRejected,
            ));
        }
        AgentStatus::Expired => {
            return Err(FlowError::code(
                StatusCode::FORBIDDEN,
                crate::AgentAuthErrorCode::AgentExpired,
            ));
        }
        AgentStatus::Claimed => {
            return Err(FlowError::code(
                StatusCode::BAD_REQUEST,
                crate::AgentAuthErrorCode::InvalidRequest,
            ));
        }
    }
    Ok(agent)
}

fn approval(agent: &crate::AgentIdentity, user_code: &str) -> AgentApprovalRequest {
    let now = Utc::now();
    AgentApprovalRequest {
        id: Uuid::new_v4().to_string(),
        method: AgentApprovalMethod::DeviceAuthorization,
        agent_id: Some(agent.id.clone()),
        host_id: Some(agent.host_id.clone()),
        user_id: agent.user_id,
        capabilities: None,
        status: AgentApprovalStatus::Pending,
        user_code_hash: Some(hash_token(user_code)),
        login_hint: None,
        binding_message: None,
        client_notification_token: None,
        client_notification_endpoint: None,
        delivery_mode: None,
        interval: APPROVAL_INTERVAL,
        last_polled_at: None,
        expires_at: now + Duration::seconds(APPROVAL_EXPIRES_IN),
        created_at: now,
        updated_at: now,
    }
}

fn verification_page(configured: &str, origin: &str) -> String {
    let configured = configured.trim_end_matches('/');
    if configured.starts_with("http://") || configured.starts_with("https://") {
        configured.to_owned()
    } else {
        format!("{origin}/{}", configured.trim_start_matches('/'))
    }
}
