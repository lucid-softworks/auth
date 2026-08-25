#![allow(clippy::result_large_err)] // Axum responses are the deliberate error channel.

use super::lifecycle::{
    reactivate_for_host, revoke_authorized, rotate_for_host, status_authorized,
};
use crate::agent_auth::axum::agent::{
    error::{AgentError, response},
    model::{ReactivateBody, RevokeBody, RotateKeyBody, StatusQuery},
};
use crate::{
    AuthService,
    agent_auth::axum::{
        AgentAuthState, auth,
        input::{AgentJson, AgentQuery},
        issuer,
    },
};
use axum::{
    Extension,
    extract::OriginalUri,
    http::{HeaderMap, Method, Uri},
    response::Response,
};
use chrono::Utc;
use serde::Serialize;
use std::sync::Arc;

pub(in crate::agent_auth::axum) async fn revoke(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    AgentJson(body): AgentJson<RevokeBody>,
) -> Response {
    let authentication = match authenticate(
        &service,
        &state,
        &headers,
        &uri,
        Method::POST,
        "/agent/revoke",
        Some(&body),
    )
    .await
    {
        Ok(authentication) => authentication,
        Err(response) => return response,
    };
    let user = crate::axum::http::current_session(&service, &headers)
        .await
        .map(|session| session.user.id);
    response(revoke_authorized(&state, authentication, user, body).await)
}

pub(in crate::agent_auth::axum) async fn rotate_key(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    AgentJson(body): AgentJson<RotateKeyBody>,
) -> Response {
    let authentication = match authenticate(
        &service,
        &state,
        &headers,
        &uri,
        Method::POST,
        "/agent/rotate-key",
        Some(&body),
    )
    .await
    {
        Ok(authentication) => authentication,
        Err(response) => return response,
    };
    let auth::ScopedAgentAuthentication::Host(host) = authentication else {
        return AgentError::unauthorized_session().into_response();
    };
    response(rotate_for_host(&state, &host, body).await)
}

pub(in crate::agent_auth::axum) async fn reactivate(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    AgentJson(body): AgentJson<ReactivateBody>,
) -> Response {
    let authentication = match authenticate(
        &service,
        &state,
        &headers,
        &uri,
        Method::POST,
        "/agent/reactivate",
        Some(&body),
    )
    .await
    {
        Ok(authentication) => authentication,
        Err(response) => return response,
    };
    let auth::ScopedAgentAuthentication::Host(host) = authentication else {
        return AgentError::unauthorized_session().into_response();
    };
    response(reactivate_for_host(&state, &host, &body.agent_id, Utc::now()).await)
}

pub(in crate::agent_auth::axum) async fn status(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    AgentQuery(query): AgentQuery<StatusQuery>,
) -> Response {
    let authentication = match authenticate::<()>(
        &service,
        &state,
        &headers,
        &uri,
        Method::GET,
        "/agent/status",
        None,
    )
    .await
    {
        Ok(authentication) => authentication,
        Err(response) => return response,
    };
    response(status_authorized(&state, authentication, query.agent_id).await)
}

async fn authenticate<T: Serialize>(
    service: &AuthService,
    state: &AgentAuthState,
    headers: &HeaderMap,
    uri: &Uri,
    method: Method,
    path: &str,
    body: Option<&T>,
) -> Result<auth::ScopedAgentAuthentication, Response> {
    let serialized = body.and_then(|body| serde_json::to_string(body).ok());
    let base_url = issuer(service, headers);
    let url = auth::request_url(service, headers, uri);
    auth::authenticate_scoped(
        service,
        state,
        auth::AgentRequestContext {
            path,
            method: method.as_str(),
            base_url: &base_url,
            url: &url,
            headers,
            serialized_body: serialized.as_deref(),
        },
    )
    .await
    .map_err(|error| auth::error_response(error, &base_url))
}
