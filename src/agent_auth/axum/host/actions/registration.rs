use super::token::{enrollment_token, hash_token};
use super::validation::{
    find_host_by_key, validate_capabilities, validate_jwks_url, validate_public_key,
};
use crate::{
    AgentAuthAuditEventType, AgentAuthConfig, AgentDefaultHostCapabilitiesContext,
    AgentEndpointContext, AgentHost, AgentHostClaimedContext, AgentHostEnrollment,
    AgentHostEnrollmentOutcome, AgentHostStatus, AgentMode, AgentStoreCreateOutcome,
    agent_auth::axum::{
        AgentAuthState,
        host::{
            error::{HostError, store_error},
            model::{CreateHostBody, EnrollHostBody},
        },
    },
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

const ENROLLMENT_TOKEN_TTL: i64 = 3_600;

struct Reactivation {
    body: CreateHostBody,
    serialized_key: Option<String>,
    capabilities: Vec<String>,
    endpoint: AgentEndpointContext,
    now: DateTime<Utc>,
    existing: AgentHost,
}

pub(in crate::agent_auth::axum::host) async fn create_for_user(
    state: &AgentAuthState,
    user_id: &str,
    body: CreateHostBody,
    endpoint: AgentEndpointContext,
    now: DateTime<Utc>,
) -> Result<Value, HostError> {
    validate_jwks_url(body.jwks_url.as_deref())?;
    let serialized_key = body
        .public_key
        .as_ref()
        .map(|key| validate_public_key(key, &state.config))
        .transpose()?;
    let capabilities = resolve_capabilities(state, user_id, &body, &endpoint).await;
    validate_capabilities(&capabilities, &state.config).await?;
    let existing = match body.public_key.as_ref() {
        Some(key) => find_host_by_key(&state.store, key).await?,
        None => None,
    };
    if let Some(existing) = existing {
        return reactivate_host(
            state,
            user_id,
            Reactivation {
                body,
                serialized_key,
                capabilities,
                endpoint,
                now,
                existing,
            },
        )
        .await;
    }
    create_new_host(state, user_id, body, serialized_key, capabilities, now).await
}

async fn resolve_capabilities(
    state: &AgentAuthState,
    user_id: &str,
    body: &CreateHostBody,
    endpoint: &AgentEndpointContext,
) -> Vec<String> {
    match &body.default_capabilities {
        Some(capabilities) => capabilities.clone(),
        None => match &state.config.resolve_default_host_capabilities {
            Some(resolve) => {
                resolve
                    .resolve(AgentDefaultHostCapabilitiesContext {
                        endpoint: endpoint.clone(),
                        mode: AgentMode::Delegated,
                        user_id: Some(user_id.to_owned()),
                        host_id: None,
                        host_name: body.name.clone(),
                    })
                    .await
            }
            None => state.config.default_host_capabilities.clone(),
        },
    }
}

async fn reactivate_host(
    state: &AgentAuthState,
    user_id: &str,
    reactivation: Reactivation,
) -> Result<Value, HostError> {
    let Reactivation {
        body,
        serialized_key,
        capabilities,
        endpoint,
        now,
        mut existing,
    } = reactivation;
    if existing.status == AgentHostStatus::Revoked {
        return Err(HostError::host_revoked());
    }
    if existing
        .user_id
        .as_deref()
        .is_some_and(|owner| owner != user_id)
    {
        return Err(HostError::host_already_linked());
    }
    let was_unclaimed = existing.user_id.is_none();
    existing.name = body.name.or(existing.name);
    existing.user_id = Some(user_id.to_owned());
    existing.default_capabilities = capabilities.clone();
    existing.public_key = serialized_key;
    existing.kid = body
        .public_key
        .as_ref()
        .and_then(|key| key.get("kid"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    existing.jwks_url = body.jwks_url;
    existing.status = AgentHostStatus::Active;
    existing.activated_at = Some(now);
    existing.expires_at = session_expiry(&state.config, now);
    existing.updated_at = now;
    state
        .store
        .update_host(existing.clone())
        .await
        .map_err(store_error)?;
    if was_unclaimed && let Some(callback) = &state.config.on_host_claimed {
        callback
            .call(AgentHostClaimedContext {
                endpoint,
                host_id: existing.id.clone(),
                user_id: user_id.to_owned(),
                previous_user_id: None,
            })
            .await;
    }
    super::super::events::emit(
        state,
        AgentAuthAuditEventType::HostReactivated,
        Some(user_id.to_string()),
        None,
        existing.id.clone(),
        serde_json::Map::from_iter([("defaultCapabilities".into(), json!(capabilities))]),
    );
    Ok(json!({
        "hostId": existing.id,
        "default_capabilities": capabilities,
        "status": "active"
    }))
}

async fn create_new_host(
    state: &AgentAuthState,
    user_id: &str,
    body: CreateHostBody,
    serialized_key: Option<String>,
    capabilities: Vec<String>,
    now: DateTime<Utc>,
) -> Result<Value, HostError> {
    let enrollment = body.public_key.is_none() && body.jwks_url.is_none();
    let (token, token_hash) = enrollment.then(enrollment_token).unzip();
    let host = AgentHost {
        id: Uuid::new_v4().to_string(),
        name: body.name,
        user_id: Some(user_id.to_owned()),
        default_capabilities: capabilities.clone(),
        public_key: serialized_key,
        kid: body
            .public_key
            .as_ref()
            .and_then(|key| key.get("kid"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        jwks_url: body.jwks_url,
        enrollment_token_hash: token_hash,
        enrollment_token_expires_at: enrollment
            .then_some(now + ChronoDuration::seconds(ENROLLMENT_TOKEN_TTL)),
        status: if enrollment {
            AgentHostStatus::PendingEnrollment
        } else {
            AgentHostStatus::Active
        },
        activated_at: (!enrollment).then_some(now),
        expires_at: (!enrollment)
            .then(|| session_expiry(&state.config, now))
            .flatten(),
        last_used_at: None,
        created_at: now,
        updated_at: now,
    };
    let created = match state.store.create_host(host).await.map_err(store_error)? {
        AgentStoreCreateOutcome::Created(host) => host,
        AgentStoreCreateOutcome::UniqueConflict => return Err(HostError::internal()),
    };
    super::super::events::emit(
        state,
        AgentAuthAuditEventType::HostCreated,
        Some(user_id.to_string()),
        None,
        created.id.clone(),
        serde_json::Map::from_iter([
            ("defaultCapabilities".into(), json!(capabilities)),
            (
                "status".into(),
                json!(if enrollment {
                    "pending_enrollment"
                } else {
                    "active"
                }),
            ),
        ]),
    );
    if enrollment {
        Ok(json!({
            "hostId": created.id,
            "default_capabilities": capabilities,
            "status": "pending_enrollment",
            "enrollmentToken": token,
            "enrollmentTokenExpiresAt": created.enrollment_token_expires_at
        }))
    } else {
        Ok(json!({
            "hostId": created.id,
            "default_capabilities": capabilities,
            "status": "active"
        }))
    }
}

pub(in crate::agent_auth::axum::host) async fn enroll_with_token(
    state: &AgentAuthState,
    body: EnrollHostBody,
    endpoint: AgentEndpointContext,
    now: DateTime<Utc>,
) -> Result<Value, HostError> {
    let serialized_key = validate_public_key(&body.public_key, &state.config)?;
    let token_hash = hash_token(&body.token);
    let provisioned = state
        .store
        .find_host_by_enrollment_token_hash(&token_hash)
        .await
        .map_err(store_error)?;
    let event_name = body
        .name
        .clone()
        .or_else(|| provisioned.as_ref().and_then(|host| host.name.clone()));
    let existing = find_host_by_key(&state.store, &body.public_key).await?;
    let claimed_user = existing
        .as_ref()
        .filter(|existing| existing.user_id.is_none())
        .and_then(|existing| {
            provisioned
                .as_ref()
                .and_then(|provisioned| provisioned.user_id.clone())
                .map(|user_id| (existing.id.clone(), user_id))
        });
    let kid = body
        .public_key
        .get("kid")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let outcome = state
        .store
        .enroll_host(
            &token_hash,
            AgentHostEnrollment {
                public_key: serialized_key,
                kid,
                name: body.name,
                now,
                expires_at: session_expiry(&state.config, now),
            },
        )
        .await
        .map_err(store_error)?;
    let enrolled = enrolled_host(outcome)?;
    notify_claimed_host(state, &enrolled, claimed_user, endpoint).await;
    if provisioned
        .as_ref()
        .is_some_and(|provisioned| provisioned.id == enrolled.id)
    {
        let mut metadata = serde_json::Map::new();
        if let Some(name) = event_name {
            metadata.insert("name".into(), json!(name));
        }
        super::super::events::emit(
            state,
            AgentAuthAuditEventType::HostEnrolled,
            None,
            Some("system"),
            enrolled.id.clone(),
            metadata,
        );
    }
    Ok(enrolled_json(&enrolled))
}

fn enrolled_host(outcome: AgentHostEnrollmentOutcome) -> Result<AgentHost, HostError> {
    let host = match outcome {
        AgentHostEnrollmentOutcome::Enrolled(host) => *host,
        AgentHostEnrollmentOutcome::TokenNotFound => {
            return Err(HostError::enrollment_token_invalid());
        }
        AgentHostEnrollmentOutcome::TokenExpired => {
            return Err(HostError::enrollment_token_expired());
        }
        AgentHostEnrollmentOutcome::HostNotPendingEnrollment => {
            return Err(HostError::not_pending_enrollment());
        }
        AgentHostEnrollmentOutcome::PublicKeyHostRevoked => {
            return Err(HostError::host_revoked());
        }
        AgentHostEnrollmentOutcome::HostAlreadyLinked => {
            return Err(HostError::host_already_linked());
        }
    };
    Ok(host)
}

async fn notify_claimed_host(
    state: &AgentAuthState,
    enrolled: &AgentHost,
    claimed_user: Option<(String, String)>,
    endpoint: AgentEndpointContext,
) {
    if let Some((host_id, user_id)) = claimed_user
        && enrolled.id == host_id
        && let Some(callback) = &state.config.on_host_claimed
    {
        callback
            .call(AgentHostClaimedContext {
                endpoint,
                host_id,
                user_id,
                previous_user_id: None,
            })
            .await;
    }
}

fn enrolled_json(host: &AgentHost) -> Value {
    json!({
        "hostId": host.id,
        "name": host.name,
        "default_capabilities": host.default_capabilities,
        "status": "active"
    })
}

pub(super) fn session_expiry(
    config: &AgentAuthConfig,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    (config.agent_session_ttl > 0)
        .then(|| ChronoDuration::seconds(config.agent_session_ttl as i64))
        .and_then(|duration| now.checked_add_signed(duration))
}

#[cfg(test)]
#[path = "registration_tests.rs"]
mod tests;
