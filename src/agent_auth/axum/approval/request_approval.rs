use super::{
    error::Result,
    support::{APPROVAL_EXPIRES_IN, APPROVAL_INTERVAL, generate_user_code, hash_token},
};
use crate::{
    AgentApprovalMethod, AgentApprovalMethodContext, AgentApprovalRequest, AgentApprovalStatus,
    AuthService, agent_auth::axum::AgentAuthState,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) struct BuiltApproval {
    pub(super) record: AgentApprovalRequest,
    pub(super) response: Value,
}

pub(super) struct BuildRequest<'a> {
    pub(super) origin: &'a str,
    pub(super) agent: &'a crate::AgentIdentity,
    pub(super) user_id: Option<String>,
    pub(super) capabilities: Vec<String>,
    pub(super) preferred: Option<String>,
    pub(super) login_hint: Option<String>,
    pub(super) binding_message: Option<String>,
}

struct ApprovalRecordInput {
    user_id: Option<String>,
    capabilities: Vec<String>,
    method: AgentApprovalMethod,
    user_code_hash: Option<String>,
    login_hint: Option<String>,
    binding_message: Option<String>,
    now: chrono::DateTime<Utc>,
}

pub(super) async fn build(
    service: &AuthService,
    state: &AgentAuthState,
    request: BuildRequest<'_>,
) -> Result<BuiltApproval> {
    let BuildRequest {
        origin,
        agent,
        user_id,
        capabilities,
        preferred,
        login_hint,
        binding_message,
    } = request;
    let method_name = if let Some(resolver) = &state.config.resolve_approval_method {
        resolver
            .resolve(AgentApprovalMethodContext {
                user_id: user_id.clone(),
                agent_name: agent.name.clone(),
                host_id: Some(agent.host_id.clone()),
                capabilities: capabilities.clone(),
                preferred_method: preferred.clone(),
                supported_methods: state.config.approval_methods.clone(),
            })
            .await
    } else {
        preferred.unwrap_or_else(|| "device_authorization".into())
    };
    let method = method_name
        .parse::<AgentApprovalMethod>()
        .ok()
        .filter(|method| state.config.approval_methods.contains(method))
        .unwrap_or(AgentApprovalMethod::DeviceAuthorization);
    let now = Utc::now();
    if method == AgentApprovalMethod::Ciba
        && let Some(user_id) = user_id.as_deref()
        && let Some(user) = service.auth_user_by_id(user_id).await?
    {
        let approval = approval_record(
            agent,
            ApprovalRecordInput {
                user_id: Some(user_id.to_owned()),
                capabilities,
                method: AgentApprovalMethod::Ciba,
                user_code_hash: None,
                login_hint: Some(login_hint.unwrap_or(user.email)),
                binding_message: Some(
                    binding_message
                        .unwrap_or_else(|| format!("Agent \"{}\" requesting approval", agent.name)),
                ),
                now,
            },
        );
        return Ok(BuiltApproval {
            record: approval,
            response: json!({"method": "ciba", "expires_in": APPROVAL_EXPIRES_IN, "interval": APPROVAL_INTERVAL}),
        });
    }
    let code = generate_user_code();
    let approval = approval_record(
        agent,
        ApprovalRecordInput {
            user_id,
            capabilities,
            method: AgentApprovalMethod::DeviceAuthorization,
            user_code_hash: Some(hash_token(&code)),
            login_hint,
            binding_message,
            now,
        },
    );
    let id = approval.id.clone();
    let configured = state.config.device_authorization_page.trim_end_matches('/');
    let page = if configured.starts_with("http://") || configured.starts_with("https://") {
        configured.to_owned()
    } else {
        format!("{origin}/{}", configured.trim_start_matches('/'))
    };
    Ok(BuiltApproval {
        record: approval,
        response: json!({"method": "device_authorization", "device_code": id, "verification_uri": page, "verification_uri_complete": format!("{page}?agent_id={}&code={code}", agent.id), "user_code": code, "expires_in": APPROVAL_EXPIRES_IN, "interval": APPROVAL_INTERVAL}),
    })
}

fn approval_record(
    agent: &crate::AgentIdentity,
    input: ApprovalRecordInput,
) -> AgentApprovalRequest {
    AgentApprovalRequest {
        id: Uuid::new_v4().to_string(),
        method: input.method,
        agent_id: Some(agent.id.clone()),
        host_id: Some(agent.host_id.clone()),
        user_id: input.user_id,
        capabilities: Some(input.capabilities.join(" ")),
        status: AgentApprovalStatus::Pending,
        user_code_hash: input.user_code_hash,
        login_hint: input.login_hint,
        binding_message: input.binding_message,
        client_notification_token: None,
        client_notification_endpoint: None,
        delivery_mode: (input.method == AgentApprovalMethod::Ciba).then(|| "poll".into()),
        interval: APPROVAL_INTERVAL,
        last_polled_at: None,
        expires_at: input.now + Duration::seconds(APPROVAL_EXPIRES_IN),
        created_at: input.now,
        updated_at: input.now,
    }
}
