use super::{
    error::{FlowError, Result, response},
    model::ApproveCapabilityBody,
};
use crate::{
    AuthService,
    agent_auth::axum::{AgentAuthState, input::AgentJson},
};
use axum::{
    Extension,
    extract::OriginalUri,
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::Value;
use std::sync::Arc;

pub(in crate::agent_auth::axum) async fn approve_capability(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    OriginalUri(_uri): OriginalUri,
    _method: Method,
    headers: HeaderMap,
    AgentJson(body): AgentJson<ApproveCapabilityBody>,
) -> Response {
    let Some(session) = crate::axum::http::current_session(&service, &headers).await else {
        return FlowError::code(
            StatusCode::UNAUTHORIZED,
            crate::AgentAuthErrorCode::UnauthorizedSession,
        )
        .into_response();
    };
    response(run(&service, &state, session, body, &headers).await)
}

async fn run(
    service: &AuthService,
    state: &AgentAuthState,
    session: crate::SessionWithUser,
    body: ApproveCapabilityBody,
    headers: &HeaderMap,
) -> Result<Value> {
    super::approve_flow::run(service, state, session, body, headers).await
}
