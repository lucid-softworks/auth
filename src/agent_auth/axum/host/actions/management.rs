use super::validation::{validate_capabilities, validate_jwks_url, validate_public_key};
use crate::{
    AgentAuthAuditEventType, AgentHost, AgentHostRotationOutcome, AgentHostStatus,
    agent_auth::{
        axum::{
            AgentAuthState,
            host::{
                error::{HostError, store_error},
                model::{HostAuthorization, UpdateHostBody},
            },
        },
        jwt::jwk_thumbprint,
    },
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

mod switch;

pub(in crate::agent_auth::axum::host) use switch::switch_to_user;

pub(in crate::agent_auth::axum::host) async fn list_for_user(
    state: &AgentAuthState,
    user_id: &str,
    status: Option<AgentHostStatus>,
) -> Result<Value, HostError> {
    let mut hosts = state
        .store
        .list_hosts_for_user(user_id)
        .await
        .map_err(store_error)?;
    hosts.retain(|host| status.is_none_or(|status| host.status == status));
    hosts.sort_by_key(|host| std::cmp::Reverse(host.created_at));
    Ok(json!({"hosts": hosts.iter().map(host_summary).collect::<Vec<_>>() }))
}

pub(in crate::agent_auth::axum::host) async fn get_for_user(
    state: &AgentAuthState,
    user_id: &str,
    host_id: &str,
) -> Result<Value, HostError> {
    let host = state
        .store
        .find_host(host_id)
        .await
        .map_err(store_error)?
        .filter(|host| host.user_id.as_deref() == Some(user_id))
        .ok_or_else(HostError::host_not_found)?;
    Ok(host_summary(&host))
}

pub(in crate::agent_auth::axum::host) async fn revoke_authorized(
    state: &AgentAuthState,
    authorization: HostAuthorization,
    requested: Option<String>,
    now: DateTime<Utc>,
) -> Result<Value, HostError> {
    let (host_id, user_id, actor_id) = match authorization {
        HostAuthorization::Host(host) => {
            let host = *host;
            if requested.as_deref().is_some_and(|id| id != host.id) {
                return Err(HostError::unauthorized());
            }
            let actor_id = host.user_id;
            (host.id, None, actor_id)
        }
        HostAuthorization::User(user_id) => {
            let host_id = requested.ok_or_else(|| {
                HostError::invalid_request("host_id is required when using user session.")
            })?;
            (host_id, Some(user_id.clone()), Some(user_id))
        }
    };
    let host = state
        .store
        .find_host(&host_id)
        .await
        .map_err(store_error)?
        .ok_or_else(HostError::host_not_found)?;
    if let (Some(user_id), Some(owner)) = (user_id.as_deref(), host.user_id.as_deref())
        && owner != user_id
        && !shares_organization(state, user_id, owner).await
    {
        return Err(HostError::host_not_found());
    }
    if host.status == AgentHostStatus::Revoked {
        return Ok(json!({"host_id": host.id, "status": "revoked", "agents_revoked": 0}));
    }
    let agents = state
        .store
        .list_agents_for_host(&host.id)
        .await
        .map_err(store_error)?;
    let revoked = agents
        .iter()
        .filter(|agent| {
            !matches!(
                agent.status,
                crate::AgentStatus::Revoked | crate::AgentStatus::Rejected
            )
        })
        .count();
    let host = state
        .store
        .revoke_host_cascade(&host.id, now)
        .await
        .map_err(store_error)?
        .ok_or_else(HostError::host_not_found)?;
    super::super::events::emit(
        state,
        AgentAuthAuditEventType::HostRevoked,
        actor_id,
        None,
        host.id.clone(),
        serde_json::Map::from_iter([("agentsRevoked".into(), json!(revoked))]),
    );
    Ok(json!({"host_id": host.id, "status": "revoked", "agents_revoked": revoked}))
}

pub(in crate::agent_auth::axum::host) async fn update_for_user(
    state: &AgentAuthState,
    user_id: &str,
    body: UpdateHostBody,
    now: DateTime<Utc>,
) -> Result<Value, HostError> {
    validate_jwks_url(body.jwks_url.as_deref())?;
    let mut event_metadata = serde_json::Map::new();
    if let Some(name) = body.name.as_ref() {
        event_metadata.insert("name".into(), json!(name));
    }
    if let Some(capabilities) = body.default_capabilities.as_ref() {
        event_metadata.insert("defaultCapabilities".into(), json!(capabilities));
    }
    if let Some(jwks_url) = body.jwks_url.as_ref() {
        event_metadata.insert("jwksUrl".into(), json!(jwks_url));
    }
    let mut host = state
        .store
        .find_host(&body.host_id)
        .await
        .map_err(store_error)?
        .ok_or_else(HostError::host_not_found)?;
    if let Some(owner) = host.user_id.as_deref()
        && owner != user_id
        && !shares_organization(state, user_id, owner).await
    {
        return Err(HostError::host_not_found());
    }
    if host.status == AgentHostStatus::Revoked {
        return Err(HostError::host_revoked());
    }
    if let Some(name) = body.name {
        host.name = Some(name);
    }
    if let Some(public_key) = body.public_key {
        host.public_key = Some(validate_public_key(&public_key, &state.config)?);
        host.kid = public_key
            .get("kid")
            .and_then(Value::as_str)
            .map(str::to_owned);
    }
    if let Some(jwks_url) = body.jwks_url {
        host.jwks_url = Some(jwks_url);
    }
    if let Some(capabilities) = body.default_capabilities {
        validate_capabilities(&capabilities, &state.config).await?;
        host.default_capabilities = capabilities;
    }
    host.updated_at = now;
    let updated = state
        .store
        .update_host(host)
        .await
        .map_err(store_error)?
        .ok_or_else(HostError::host_not_found)?;
    super::super::events::emit(
        state,
        AgentAuthAuditEventType::HostUpdated,
        Some(user_id.to_string()),
        None,
        updated.id.clone(),
        event_metadata,
    );
    Ok(json!({
        "id": updated.id,
        "default_capabilities": updated.default_capabilities,
        "jwks_url": updated.jwks_url,
        "status": updated.status,
        "updated_at": updated.updated_at
    }))
}

async fn shares_organization(state: &AgentAuthState, user_id: &str, owner_id: &str) -> bool {
    let Some(store) = &state.organization_store else {
        return false;
    };
    let Ok(organizations) = store.list_organizations(user_id).await else {
        return false;
    };
    for organization in organizations {
        match store.find_member(organization.id, owner_id).await {
            Ok(Some(_)) => return true,
            Ok(None) => {}
            Err(_) => return false,
        }
    }
    false
}

pub(in crate::agent_auth::axum::host) async fn rotate_authorized(
    state: &AgentAuthState,
    host: AgentHost,
    public_key: Value,
    now: DateTime<Utc>,
) -> Result<Value, HostError> {
    let serialized = validate_public_key(&public_key, &state.config)?;
    let old_id = host.id.clone();
    let new_id = jwk_thumbprint(&public_key).map_err(|_| HostError::invalid_public_key())?;
    let kid = public_key
        .get("kid")
        .and_then(Value::as_str)
        .map(str::to_owned);
    match state
        .store
        .rotate_host_key(&old_id, &new_id, serialized, kid, now)
        .await
        .map_err(store_error)?
    {
        AgentHostRotationOutcome::Rotated(_) => {}
        AgentHostRotationOutcome::NotFound => return Err(HostError::host_not_found()),
        AgentHostRotationOutcome::UniqueConflict => {
            return Err(HostError::host_already_linked());
        }
    }
    super::super::events::emit(
        state,
        AgentAuthAuditEventType::HostKeyRotated,
        None,
        Some("system"),
        new_id.clone(),
        serde_json::Map::from_iter([("previousHostId".into(), json!(old_id))]),
    );
    Ok(json!({"host_id": new_id, "status": "active"}))
}

pub(super) fn host_summary(host: &AgentHost) -> Value {
    json!({
        "id": host.id,
        "name": host.name.clone().unwrap_or_else(|| format!("Device {}", prefix(&host.id))),
        "default_capabilities": host.default_capabilities,
        "status": host.status,
        "activated_at": host.activated_at,
        "expires_at": host.expires_at,
        "last_used_at": host.last_used_at,
        "created_at": host.created_at,
        "updated_at": host.updated_at
    })
}

pub(super) fn prefix(value: &str) -> &str {
    value.get(..8).unwrap_or(value)
}

#[cfg(test)]
#[path = "management_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "management_switch_tests.rs"]
mod switch_tests;
