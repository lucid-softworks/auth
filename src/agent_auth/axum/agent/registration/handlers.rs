use super::{claim::claim_inner, register::register_inner};
use crate::agent_auth::axum::agent::error::response;
use crate::agent_auth::axum::agent::model::{ClaimBody, RegisterBody};
use crate::{
    AuthService,
    agent_auth::axum::{AgentAuthState, input::AgentJson, issuer},
};
use axum::{Extension, http::HeaderMap, response::Response};
use std::sync::Arc;

pub(in crate::agent_auth::axum) async fn register(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    AgentJson(body): AgentJson<RegisterBody>,
) -> Response {
    let base_url = issuer(&service, &headers);
    response(register_inner(&state, &headers, &base_url, body).await)
}

pub(in crate::agent_auth::axum) async fn claim(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    AgentJson(body): AgentJson<ClaimBody>,
) -> Response {
    let base_url = issuer(&service, &headers);
    response(claim_inner(&state, &headers, &base_url, body).await)
}
