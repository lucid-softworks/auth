use super::{
    error::{AgentError, response},
    events, grants,
    model::{GetQuery, ListQuery, UpdateBody},
};
use crate::{
    AgentHost, AuthService,
    agent_auth::axum::{
        AgentAuthState,
        input::{AgentJson, AgentQuery, AgentRawJson},
    },
};
use axum::{Extension, http::HeaderMap, response::Response};
use chrono::Utc;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};

pub(in crate::agent_auth::axum) async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    AgentQuery(query): AgentQuery<ListQuery>,
) -> Response {
    let Some(user_id) = user_id(&service, &headers).await else {
        return AgentError::unauthorized_session().into_response();
    };
    response(list_for_user(&state, &user_id, query).await)
}

pub(in crate::agent_auth::axum) async fn get(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    AgentQuery(query): AgentQuery<GetQuery>,
) -> Response {
    let Some(user_id) = user_id(&service, &headers).await else {
        return AgentError::unauthorized_session().into_response();
    };
    response(get_for_user(&state, &user_id, &query.agent_id).await)
}

pub(in crate::agent_auth::axum) async fn update(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    AgentJson(body): AgentJson<UpdateBody>,
) -> Response {
    let Some(user_id) = user_id(&service, &headers).await else {
        return AgentError::unauthorized_session().into_response();
    };
    response(update_for_user(&state, &user_id, body).await)
}

pub(in crate::agent_auth::axum) async fn cleanup(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    _body: AgentRawJson,
) -> Response {
    let Some(user_id) = user_id(&service, &headers).await else {
        return AgentError::unauthorized_session().into_response();
    };
    response(cleanup_for_user(&state, &user_id).await)
}

async fn user_id(service: &AuthService, headers: &HeaderMap) -> Option<String> {
    crate::axum::http::current_session(service, headers)
        .await
        .map(|session| session.user.id)
}

async fn list_for_user(
    state: &AgentAuthState,
    user_id: &str,
    query: ListQuery,
) -> Result<Value, AgentError> {
    if query.limit.is_some_and(|limit| limit <= 0.0)
        || query.offset.is_some_and(|offset| offset < 0.0)
    {
        return Err(AgentError::bad("invalid_request", "Invalid query"));
    }
    let limit = query.limit.unwrap_or(50.0).min(200.0) as usize;
    let offset = query.offset.unwrap_or(0.0) as usize;
    let mut agents = state
        .store
        .list_agents_for_user(user_id)
        .await
        .map_err(AgentError::store)?;
    agents.retain(|agent| {
        query.status.is_none_or(|status| agent.status == status)
            && query.mode.is_none_or(|mode| agent.mode == mode)
            && query
                .host_id
                .as_ref()
                .is_none_or(|host_id| agent.host_id == *host_id)
    });
    agents.sort_by_key(|agent| std::cmp::Reverse(agent.created_at));
    let selected = agents.into_iter().skip(offset).take(limit);
    let mut hosts = BTreeMap::<String, Option<AgentHost>>::new();
    let mut output = Vec::new();
    for agent in selected {
        let host = match hosts.get(&agent.host_id) {
            Some(host) => host.clone(),
            None => {
                let host = state
                    .store
                    .find_host(&agent.host_id)
                    .await
                    .map_err(AgentError::store)?;
                hosts.insert(agent.host_id.clone(), host.clone());
                host
            }
        };
        let grants = state
            .store
            .list_grants(&agent.id)
            .await
            .map_err(AgentError::store)?;
        output.push(json!({
            "agent_id": agent.id,
            "name": display_name(Some(&agent.name), &agent.id, "Agent"),
            "status": agent.status,
            "mode": agent.mode,
            "host_id": agent.host_id,
            "host_name": display_name(host.as_ref().and_then(|host| host.name.as_deref()), &agent.host_id, "Device"),
            "agent_capability_grants": grants::format(grants, &state.config),
            "created_at": agent.created_at,
            "last_used_at": agent.last_used_at,
            "expires_at": agent.expires_at
        }));
    }
    Ok(json!({"agents": output}))
}

async fn get_for_user(
    state: &AgentAuthState,
    user_id: &str,
    agent_id: &str,
) -> Result<Value, AgentError> {
    let agent = state
        .store
        .find_agent(agent_id)
        .await
        .map_err(AgentError::store)?
        .filter(|agent| agent.user_id.as_deref() == Some(user_id))
        .ok_or_else(AgentError::not_found)?;
    let grants = state
        .store
        .list_grants(&agent.id)
        .await
        .map_err(AgentError::store)?;
    Ok(json!({
        "agent_id": agent.id,
        "name": display_name(Some(&agent.name), &agent.id, "Agent"),
        "status": agent.status,
        "mode": agent.mode,
        "host_id": agent.host_id,
        "user_id": agent.user_id,
        "agent_capability_grants": grants::format(grants, &state.config),
        "metadata": agent.metadata,
        "created_at": agent.created_at,
        "activated_at": agent.activated_at,
        "last_used_at": agent.last_used_at,
        "expires_at": agent.expires_at
    }))
}

async fn update_for_user(
    state: &AgentAuthState,
    user_id: &str,
    body: UpdateBody,
) -> Result<Value, AgentError> {
    let event_name = body.name.clone();
    let event_metadata = body.metadata.clone();
    if body.metadata.as_ref().is_some_and(|metadata| {
        metadata.values().any(|value| {
            !matches!(
                value,
                Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null
            )
        })
    }) {
        return Err(AgentError::bad("invalid_request", "Invalid metadata"));
    }
    let mut agent = state
        .store
        .find_agent(&body.agent_id)
        .await
        .map_err(AgentError::store)?
        .filter(|agent| agent.user_id.as_deref() == Some(user_id))
        .ok_or_else(AgentError::not_found)?;
    if let Some(name) = body.name {
        agent.name = name;
    }
    if let Some(metadata) = body.metadata {
        agent.metadata = Some(metadata);
    }
    let updated_at = Utc::now();
    agent.updated_at = updated_at;
    let agent = state
        .store
        .update_agent(agent)
        .await
        .map_err(AgentError::store)?
        .ok_or_else(AgentError::not_found)?;
    events::emit(
        state,
        crate::AgentAuthAuditEventType::AgentUpdated,
        Some(user_id.to_string()),
        None,
        Some(agent.id.clone()),
        Some(agent.host_id.clone()),
        Some(serde_json::Map::from_iter([
            ("name".into(), json!(event_name)),
            ("metadata".into(), json!(event_metadata)),
        ])),
    )
    .await;
    Ok(json!({
        "agent_id": agent.id,
        "name": agent.name,
        "metadata": agent.metadata,
        "updated_at": updated_at
    }))
}

async fn cleanup_for_user(state: &AgentAuthState, user_id: &str) -> Result<Value, AgentError> {
    let outcome = state
        .store
        .cleanup_expired_for_user(user_id, Utc::now())
        .await
        .map_err(AgentError::store)?;
    if !outcome.agent_ids.is_empty() {
        events::emit(
            state,
            crate::AgentAuthAuditEventType::AgentCleanup,
            Some(user_id.to_string()),
            None,
            None,
            None,
            Some(serde_json::Map::from_iter([
                ("count".into(), json!(outcome.agent_ids.len())),
                ("agentIds".into(), json!(outcome.agent_ids)),
                ("approvalsExpired".into(), json!(outcome.approval_ids.len())),
            ])),
        )
        .await;
    }
    Ok(json!({
        "expired": outcome.agent_ids.len(),
        "approvals_expired": outcome.approval_ids.len()
    }))
}

fn display_name<'a>(name: Option<&'a str>, id: &'a str, prefix: &str) -> String {
    name.filter(|name| !name.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{prefix} {}", id.get(..8).unwrap_or(id)))
}
