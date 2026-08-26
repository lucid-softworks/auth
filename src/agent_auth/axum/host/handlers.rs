use super::{
    actions::{
        create_for_user, enroll_with_token, get_for_user, list_for_user, revoke_authorized,
        rotate_authorized, switch_to_user, update_for_user,
    },
    auth::host_authorization,
    error::{HostError, result_response},
    model::{
        CreateHostBody, EnrollHostBody, GetHostQuery, HostAuthorization, ListHostsQuery,
        RevokeHostBody, RotateHostKeyBody, SwitchHostAccountBody, UpdateHostBody,
    },
};
use crate::agent_auth::axum::{
    AgentAuthState,
    input::{AgentJson, AgentQuery},
    issuer,
};
use crate::{AgentEndpointContext, AuthService};
use axum::{
    Extension,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use std::{collections::BTreeMap, sync::Arc};

pub(in crate::agent_auth::axum) async fn create(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    AgentJson(body): AgentJson<CreateHostBody>,
) -> Response {
    let Some(session) = crate::axum::http::current_session(&service, &headers).await else {
        return HostError::unauthorized_session().into_response();
    };
    let endpoint = endpoint_context(&service, &headers, "POST", "/host/create");
    result_response(create_for_user(&state, &session.user.id, body, endpoint, Utc::now()).await)
}

pub(in crate::agent_auth::axum) async fn enroll(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    AgentJson(body): AgentJson<EnrollHostBody>,
) -> Response {
    let endpoint = endpoint_context(&service, &headers, "POST", "/host/enroll");
    result_response(enroll_with_token(&state, body, endpoint, Utc::now()).await)
}

pub(in crate::agent_auth::axum) async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    AgentQuery(query): AgentQuery<ListHostsQuery>,
) -> Response {
    let Some(session) = crate::axum::http::current_session(&service, &headers).await else {
        return HostError::unauthorized_session().into_response();
    };
    result_response(list_for_user(&state, &session.user.id, query.status).await)
}

pub(in crate::agent_auth::axum) async fn get(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    AgentQuery(query): AgentQuery<GetHostQuery>,
) -> Response {
    let Some(session) = crate::axum::http::current_session(&service, &headers).await else {
        return HostError::unauthorized_session().into_response();
    };
    result_response(get_for_user(&state, &session.user.id, &query.host_id).await)
}

pub(in crate::agent_auth::axum) async fn revoke(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    AgentJson(body): AgentJson<RevokeHostBody>,
) -> Response {
    let user = crate::axum::http::current_session(&service, &headers)
        .await
        .map(|session| session.user.id);
    let requested = body.host_id;
    let authorization =
        match host_authorization(&service, &state, &state.host_auth, &headers, true).await {
            Ok(Some(host)) => HostAuthorization::Host(Box::new(host)),
            Ok(None) if user.is_some() => HostAuthorization::User(user.expect("checked")),
            Ok(None) => return HostError::unauthorized_session().into_response(),
            Err(error) => return error.into_response(),
        };
    result_response(revoke_authorized(&state, authorization, requested, Utc::now()).await)
}

pub(in crate::agent_auth::axum) async fn switch_account(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    AgentJson(body): AgentJson<SwitchHostAccountBody>,
) -> Response {
    let Some(session) = crate::axum::http::current_session(&service, &headers).await else {
        return HostError::unauthorized_session().into_response();
    };
    let endpoint = endpoint_context(&service, &headers, "POST", "/host/switch-account");
    result_response(
        switch_to_user(
            &state,
            &session.user.id,
            &body.host_id,
            endpoint,
            Utc::now(),
        )
        .await,
    )
}

pub(in crate::agent_auth::axum) async fn update(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    AgentJson(body): AgentJson<UpdateHostBody>,
) -> Response {
    let Some(session) = crate::axum::http::current_session(&service, &headers).await else {
        return HostError::unauthorized_session().into_response();
    };
    result_response(update_for_user(&state, &session.user.id, body, Utc::now()).await)
}

pub(in crate::agent_auth::axum) async fn rotate_key(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    AgentJson(body): AgentJson<RotateHostKeyBody>,
) -> Response {
    let host = match host_authorization(&service, &state, &state.host_auth, &headers, false).await {
        Ok(Some(host)) => host,
        Ok(None) => return HostError::invalid_jwt().into_response(),
        Err(error) => return error.into_response(),
    };
    result_response(rotate_authorized(&state, host, body.public_key, Utc::now()).await)
}

fn endpoint_context(
    service: &AuthService,
    headers: &HeaderMap,
    method: &str,
    path: &str,
) -> AgentEndpointContext {
    let headers = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect::<BTreeMap<_, _>>();
    AgentEndpointContext {
        method: method.to_owned(),
        path: path.to_owned(),
        base_url: issuer(service, &headers_to_header_map(&headers)),
        headers,
    }
}

fn headers_to_header_map(headers: &BTreeMap<String, String>) -> HeaderMap {
    headers
        .iter()
        .filter_map(|(name, value)| {
            Some((
                name.parse::<axum::http::HeaderName>().ok()?,
                value.parse::<axum::http::HeaderValue>().ok()?,
            ))
        })
        .collect()
}
