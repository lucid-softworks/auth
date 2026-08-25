mod pending;

use super::support::{
    budget, build_grants, duration, origin, sanitize, validate_capabilities, validate_key,
    validate_required_constraints,
};
use crate::{
    AgentIdentity, AgentMode, AgentRegistrationBundle, AgentRegistrationOutcome, AgentStatus,
    agent_auth::axum::{
        AgentAuthState,
        agent::{
            approval::{self, ApprovalInput},
            bootstrap,
            error::AgentError,
            grants,
            model::RegisterBody,
        },
    },
};
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use pending::pending_response;
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) async fn register_inner(
    state: &AgentAuthState,
    headers: &HeaderMap,
    base_url: &str,
    body: RegisterBody,
) -> Result<Value, AgentError> {
    let material = registration_material(state, headers, base_url, &body).await?;
    let plan = capability_plan(state, &body, &material).await?;
    if let Some(existing) = duplicate_agent(state, &material).await? {
        if existing.status != AgentStatus::Pending {
            return Err(agent_exists());
        }
        return pending_response(state, base_url, existing, &body, plan.requested).await;
    }
    persist_registration(state, base_url, body, material, plan).await
}

struct RegistrationMaterial {
    mode: AgentMode,
    host: crate::AgentHost,
    new_host: Option<crate::AgentHost>,
    public_key: Option<Value>,
    jwks_url: Option<String>,
    key: String,
}

struct CapabilityPlan {
    normalized: Vec<crate::AgentCapabilityRequest>,
    requested: Vec<String>,
    active: Vec<String>,
    pending: Vec<String>,
    force_approval: bool,
    delegated_without_user: bool,
    needs_approval: bool,
}

struct AgentKeyMaterial {
    public_key: Option<Value>,
    jwks_url: Option<String>,
    serialized: String,
}

async fn registration_material(
    state: &AgentAuthState,
    headers: &HeaderMap,
    base_url: &str,
    body: &RegisterBody,
) -> Result<RegistrationMaterial, AgentError> {
    let mode = validate_registration_mode(state, body)?;
    let bootstrap = bootstrap::verify(
        state,
        headers,
        base_url,
        "/agent/register",
        mode,
        body.host_name.as_deref().map(|name| sanitize(name, 200)),
    )
    .await?;
    let (host, new_host) = prepare_host(state, mode, bootstrap.host, bootstrap.new_host).await?;
    enforce_limit(state, host.user_id).await?;
    let key = agent_key_material(state, &bootstrap.claims)?;
    Ok(RegistrationMaterial {
        mode,
        host,
        new_host,
        public_key: key.public_key,
        jwks_url: key.jwks_url,
        key: key.serialized,
    })
}

fn validate_registration_mode(
    state: &AgentAuthState,
    body: &RegisterBody,
) -> Result<AgentMode, AgentError> {
    if body.name.is_empty() {
        return Err(AgentError::bad("invalid_request", "Invalid request"));
    }
    let mode = body.mode.unwrap_or(AgentMode::Delegated);
    if !state.config.modes.contains(&mode) {
        return Err(AgentError::bad(
            "unsupported_mode",
            "Agent mode is not supported",
        ));
    }
    Ok(mode)
}

async fn prepare_host(
    state: &AgentAuthState,
    mode: AgentMode,
    mut host: crate::AgentHost,
    mut new_host: Option<crate::AgentHost>,
) -> Result<(crate::AgentHost, Option<crate::AgentHost>), AgentError> {
    if mode == AgentMode::Autonomous && host.user_id.is_some() {
        return Err(AgentError::bad(
            "unsupported_mode",
            "Agent mode is not supported",
        ));
    }
    if mode == AgentMode::Autonomous && host.status == crate::AgentHostStatus::Pending {
        host.status = crate::AgentHostStatus::Active;
        host.activated_at = Some(Utc::now());
        host.updated_at = Utc::now();
        state
            .store
            .update_host(host.clone())
            .await
            .map_err(AgentError::store)?;
    }
    if new_host.is_some() {
        new_host = Some(host.clone());
    }
    Ok((host, new_host))
}

fn agent_key_material(
    state: &AgentAuthState,
    claims: &serde_json::Map<String, Value>,
) -> Result<AgentKeyMaterial, AgentError> {
    let public_key = claims
        .get("agent_public_key")
        .filter(|value| value.is_object())
        .cloned();
    let jwks_url = claims
        .get("agent_jwks_url")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if public_key.is_none() && jwks_url.is_none() {
        return Err(AgentError::bad(
            "invalid_public_key",
            "Public key is invalid or malformed",
        ));
    }
    if let Some(key) = public_key.as_ref() {
        validate_key(key, &state.config.allowed_key_algorithms)?;
    }
    let serialized = public_key
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| AgentError::bad("invalid_public_key", "Public key is invalid or malformed"))?
        .unwrap_or_default();
    Ok(AgentKeyMaterial {
        public_key,
        jwks_url,
        serialized,
    })
}

async fn enforce_limit(state: &AgentAuthState, user_id: Option<Uuid>) -> Result<(), AgentError> {
    if state.config.max_agents_per_user == 0 || user_id.is_none() {
        return Ok(());
    }
    let active = state
        .store
        .list_agents_for_user(user_id.expect("checked"))
        .await
        .map_err(AgentError::store)?
        .into_iter()
        .filter(|agent| agent.status == AgentStatus::Active)
        .count();
    if active >= state.config.max_agents_per_user as usize {
        return Err(AgentError::bad(
            "agent_limit_reached",
            "Maximum number of active agents reached",
        ));
    }
    Ok(())
}

async fn capability_plan(
    state: &AgentAuthState,
    body: &RegisterBody,
    material: &RegistrationMaterial,
) -> Result<CapabilityPlan, AgentError> {
    let normalized = body.capabilities.clone().unwrap_or_default();
    validate_required_constraints(&normalized, state)?;
    let requested_input = normalized
        .iter()
        .map(|request| request.name().to_owned())
        .collect::<Vec<_>>();
    let (mut active, mut pending) = budget(&material.host.default_capabilities, &requested_input);
    if material.mode == AgentMode::Autonomous && material.host.user_id.is_none() {
        pending.clear();
    }
    validate_capabilities(state, active.iter().chain(&pending).cloned().collect()).await?;
    let requested = active.iter().chain(&pending).cloned().collect();
    let delegated_without_user =
        material.mode == AgentMode::Delegated && material.host.user_id.is_none();
    let force_approval = body.force_approval.unwrap_or(false);
    if (force_approval || delegated_without_user) && !active.is_empty() {
        pending.splice(0..0, active.drain(..));
    }
    let needs_approval = force_approval
        || material.host.status == crate::AgentHostStatus::Pending
        || !pending.is_empty()
        || delegated_without_user;
    Ok(CapabilityPlan {
        normalized,
        requested,
        active,
        pending,
        force_approval,
        delegated_without_user,
        needs_approval,
    })
}

async fn duplicate_agent(
    state: &AgentAuthState,
    material: &RegistrationMaterial,
) -> Result<Option<AgentIdentity>, AgentError> {
    if material.key.is_empty() {
        return Ok(None);
    }
    Ok(state
        .store
        .list_agents_for_host(&material.host.id)
        .await
        .map_err(AgentError::store)?
        .into_iter()
        .find(|agent| agent.public_key == material.key))
}

async fn persist_registration(
    state: &AgentAuthState,
    base_url: &str,
    body: RegisterBody,
    material: RegistrationMaterial,
    plan: CapabilityPlan,
) -> Result<Value, AgentError> {
    let now = Utc::now();
    let agent = build_agent(state, &body, &material, &plan, now);
    let grant_rows = build_grants(
        state,
        &agent,
        &plan.normalized,
        &plan.active,
        &plan.pending,
        body.reason.as_deref(),
        now,
    )
    .await?;
    let built_approval = if plan.needs_approval {
        Some(
            approval::build(
                &state.config,
                ApprovalInput {
                    origin: &origin(base_url),
                    agent_id: &agent.id,
                    agent_name: &agent.name,
                    host_id: &agent.host_id,
                    user_id: agent.user_id,
                    capabilities: &plan.requested,
                    preferred_method: body.preferred_method.as_deref(),
                    login_hint: body.login_hint.as_deref(),
                    binding_message: body
                        .binding_message
                        .as_deref()
                        .map(|message| sanitize(message, 500)),
                },
            )
            .await,
        )
    } else {
        None
    };
    let bundle = AgentRegistrationBundle {
        host: material.new_host,
        agent: agent.clone(),
        grants: grant_rows.clone(),
        approval: built_approval.as_ref().map(|built| built.record.clone()),
    };
    match state
        .store
        .register_agent_bundle(bundle)
        .await
        .map_err(AgentError::store)?
    {
        AgentRegistrationOutcome::Registered(_) => {}
        AgentRegistrationOutcome::UniqueConflict => return Err(agent_exists()),
    }
    emit_created(state, &agent, &plan).await;
    Ok(registration_response(
        state,
        agent,
        grant_rows,
        built_approval.map(|built| built.response),
    ))
}

fn build_agent(
    state: &AgentAuthState,
    body: &RegisterBody,
    material: &RegistrationMaterial,
    plan: &CapabilityPlan,
    now: chrono::DateTime<Utc>,
) -> AgentIdentity {
    AgentIdentity {
        id: Uuid::new_v4().to_string(),
        name: sanitize(&body.name, 200),
        user_id: (!plan.force_approval && !plan.delegated_without_user)
            .then_some(material.host.user_id)
            .flatten(),
        host_id: material.host.id.clone(),
        status: if plan.needs_approval {
            AgentStatus::Pending
        } else {
            AgentStatus::Active
        },
        mode: material.mode,
        public_key: material.key.clone(),
        kid: material
            .public_key
            .as_ref()
            .and_then(|key| key.get("kid"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        jwks_url: material.jwks_url.clone(),
        last_used_at: None,
        activated_at: (!plan.needs_approval).then_some(now),
        expires_at: (!plan.needs_approval && state.config.agent_session_ttl > 0)
            .then_some(now + duration(state.config.agent_session_ttl)),
        metadata: None,
        created_at: now,
        updated_at: now,
    }
}

fn registration_response(
    state: &AgentAuthState,
    agent: AgentIdentity,
    all_grants: Vec<crate::AgentCapabilityGrant>,
    approval: Option<Value>,
) -> Value {
    let mut output = json!({
        "agent_id": agent.id,
        "host_id": agent.host_id,
        "name": agent.name,
        "mode": agent.mode,
        "status": agent.status,
        "agent_capability_grants": grants::format(all_grants, &state.config)
    });
    if let Some(approval) = approval {
        output["approval"] = approval;
    }
    output
}

async fn emit_created(state: &AgentAuthState, agent: &AgentIdentity, plan: &CapabilityPlan) {
    let mut metadata = serde_json::Map::from_iter([
        ("name".into(), json!(agent.name)),
        ("mode".into(), json!(agent.mode)),
        ("capabilities".into(), json!(plan.active)),
        ("pendingCapabilities".into(), json!(plan.pending)),
    ]);
    if plan.force_approval {
        metadata.insert("forceApproval".into(), json!(true));
    }
    super::super::events::emit(
        state,
        crate::AgentAuthAuditEventType::AgentCreated,
        agent.user_id.map(|user_id| user_id.to_string()),
        None,
        Some(agent.id.clone()),
        Some(agent.host_id.clone()),
        Some(metadata),
    )
    .await;
}

fn agent_exists() -> AgentError {
    AgentError::new(
        StatusCode::CONFLICT,
        "agent_exists",
        "An agent with this key already exists",
    )
}
