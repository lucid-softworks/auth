use super::error::AgentError;
use crate::{
    AgentApprovalMethod, AgentApprovalMethodContext, AgentApprovalRequest, AgentApprovalStatus,
    AgentAuthConfig, AgentAuthStore, AgentStoreCreateOutcome,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use rand::RngExt as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use uuid::Uuid;

const EXPIRES_IN: i64 = 300;
const INTERVAL: f64 = 5.0;

pub(super) struct ApprovalInput<'a> {
    pub(super) origin: &'a str,
    pub(super) agent_id: &'a str,
    pub(super) agent_name: &'a str,
    pub(super) host_id: &'a str,
    pub(super) user_id: Option<String>,
    pub(super) capabilities: &'a [String],
    pub(super) preferred_method: Option<&'a str>,
    pub(super) login_hint: Option<&'a str>,
    pub(super) binding_message: Option<String>,
}

pub(super) struct BuiltApproval {
    pub(super) record: AgentApprovalRequest,
    pub(super) response: Value,
}

pub(super) async fn create(
    store: &Arc<dyn AgentAuthStore>,
    config: &AgentAuthConfig,
    input: ApprovalInput<'_>,
) -> Result<Value, AgentError> {
    let built = build(config, input).await;
    persist(store, built.record).await?;
    Ok(built.response)
}

pub(super) async fn build(config: &AgentAuthConfig, input: ApprovalInput<'_>) -> BuiltApproval {
    let origin = input.origin;
    let agent_id = input.agent_id;
    let preferred = input.preferred_method.map(str::to_owned);
    let method_name = match &config.resolve_approval_method {
        Some(resolver) => {
            resolver
                .resolve(AgentApprovalMethodContext {
                    user_id: input.user_id.clone(),
                    agent_name: input.agent_name.to_owned(),
                    host_id: Some(input.host_id.to_owned()),
                    capabilities: input.capabilities.to_vec(),
                    preferred_method: preferred.clone(),
                    supported_methods: config.approval_methods.clone(),
                })
                .await
        }
        None => preferred.unwrap_or_else(|| "device_authorization".into()),
    };
    let method = parse_method(&method_name)
        .filter(|method| config.approval_methods.contains(method))
        .filter(|method| *method != AgentApprovalMethod::Ciba || input.user_id.is_some())
        .unwrap_or(AgentApprovalMethod::DeviceAuthorization);
    let now = Utc::now();
    let expires_at = now + Duration::seconds(EXPIRES_IN);
    let (id, user_code, hash) = if method == AgentApprovalMethod::DeviceAuthorization {
        let code = generate_user_code();
        let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(code.as_bytes()));
        (Uuid::new_v4().to_string(), Some(code), Some(hash))
    } else {
        (Uuid::new_v4().to_string(), None, None)
    };
    let approval = AgentApprovalRequest {
        id: id.clone(),
        method,
        agent_id: Some(input.agent_id.to_owned()),
        host_id: Some(input.host_id.to_owned()),
        user_id: input.user_id,
        capabilities: (!input.capabilities.is_empty()).then(|| input.capabilities.join(" ")),
        status: AgentApprovalStatus::Pending,
        user_code_hash: hash,
        login_hint: input.login_hint.map(str::to_owned),
        binding_message: input.binding_message,
        client_notification_token: None,
        client_notification_endpoint: None,
        delivery_mode: (method == AgentApprovalMethod::Ciba).then_some("poll".into()),
        interval: INTERVAL,
        last_polled_at: None,
        expires_at,
        created_at: now,
        updated_at: now,
    };
    BuiltApproval {
        record: approval,
        response: format_response(method, config, origin, agent_id, id, user_code),
    }
}

async fn persist(
    store: &Arc<dyn AgentAuthStore>,
    approval: AgentApprovalRequest,
) -> Result<(), AgentError> {
    match store
        .create_approval(approval)
        .await
        .map_err(AgentError::store)?
    {
        AgentStoreCreateOutcome::Created(_) => {}
        AgentStoreCreateOutcome::UniqueConflict => {
            return Err(AgentError::new(
                axum::http::StatusCode::CONFLICT,
                "invalid_request",
                "Approval request already exists",
            ));
        }
    }
    Ok(())
}

fn generate_user_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rng();
    let raw = (0..8)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect::<String>();
    format!("{}-{}", &raw[..4], &raw[4..])
}

fn format_response(
    method: AgentApprovalMethod,
    config: &AgentAuthConfig,
    origin: &str,
    agent_id: &str,
    id: String,
    user_code: Option<String>,
) -> Value {
    if method == AgentApprovalMethod::Ciba {
        return json!({"method":"ciba", "expires_in":EXPIRES_IN, "interval":INTERVAL});
    }
    let page = if url::Url::parse(&config.device_authorization_page).is_ok() {
        config.device_authorization_page.clone()
    } else {
        format!(
            "{}{}",
            origin.trim_end_matches('/'),
            if config.device_authorization_page.starts_with('/') {
                ""
            } else {
                "/"
            }
        ) + &config.device_authorization_page
    };
    let user_code = user_code.expect("device flow creates a user code");
    json!({
        "method":"device_authorization",
        "device_code":id,
        "verification_uri":page,
        "verification_uri_complete":format!("{page}?agent_id={agent_id}&code={user_code}"),
        "user_code":user_code,
        "expires_in":EXPIRES_IN,
        "interval":INTERVAL
    })
}

fn parse_method(value: &str) -> Option<AgentApprovalMethod> {
    match value {
        "ciba" => Some(AgentApprovalMethod::Ciba),
        "device_authorization" => Some(AgentApprovalMethod::DeviceAuthorization),
        _ => None,
    }
}
