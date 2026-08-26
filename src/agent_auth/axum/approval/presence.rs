use super::{
    error::{FlowError, Result},
    model::ApproveCapabilityBody,
};
use crate::{AuthService, agent_auth::axum::AgentAuthState};
use axum::http::{HeaderMap, StatusCode};
use serde_json::Value;

pub(super) async fn required(
    state: &AgentAuthState,
    agent: &crate::AgentIdentity,
    agent_pending: bool,
    has_pending_grants: bool,
    capabilities: &[String],
) -> Result<bool> {
    let mut required = if agent_pending {
        state
            .store
            .find_host(&agent.host_id)
            .await?
            .is_none_or(|host| host.status == crate::AgentHostStatus::Pending)
    } else {
        has_pending_grants
    };
    if !required {
        required = capabilities.iter().any(|capability| {
            state
                .config
                .capabilities
                .iter()
                .find(|definition| definition.name == *capability)
                .is_some_and(|definition| {
                    definition.approval_strength == Some(crate::AgentApprovalStrength::Webauthn)
                })
        });
    }
    Ok(required)
}

pub(super) async fn verify(
    service: &AuthService,
    state: &AgentAuthState,
    session: &crate::SessionWithUser,
    agent_id: &str,
    body: &ApproveCapabilityBody,
    headers: &HeaderMap,
) -> Result<()> {
    if service.list_passkeys(&session.user.id).await?.is_empty() {
        return Err(FlowError::code(
            StatusCode::FORBIDDEN,
            crate::AgentAuthErrorCode::WebauthnNotEnrolled,
        ));
    }
    let config = config(service, state, headers)?;
    let Some(assertion) = &body.webauthn_response else {
        let options = service
            .start_agent_presence_verification(&config, &session.user.id, agent_id)
            .await?;
        return Err(FlowError::with_extra(
            StatusCode::FORBIDDEN,
            crate::AgentAuthErrorCode::WebauthnRequired,
            "webauthn_options",
            serde_json::to_value(options).map_err(|_| FlowError::internal())?,
        ));
    };
    let assertion = serde_json::from_value(Value::Object(assertion.clone())).map_err(|_| {
        FlowError::message(
            StatusCode::FORBIDDEN,
            crate::AgentAuthErrorCode::WebauthnVerificationFailed,
            "WebAuthn assertion verification failed.",
        )
    })?;
    service
        .finish_agent_presence_verification(&config, &session.user.id, agent_id, assertion)
        .await
        .map_err(|error| {
            let message = match error {
                crate::AuthError::PasskeyChallengeExpired => {
                    "WebAuthn challenge expired or not found. Request a new challenge."
                }
                crate::AuthError::PasskeyAuthenticationNotFound => {
                    "WebAuthn credential not recognized."
                }
                _ => "WebAuthn assertion verification failed.",
            };
            FlowError::message(
                StatusCode::FORBIDDEN,
                crate::AgentAuthErrorCode::WebauthnVerificationFailed,
                message,
            )
        })
}

fn config(
    service: &AuthService,
    state: &AgentAuthState,
    headers: &HeaderMap,
) -> Result<crate::PasskeyConfig> {
    let parsed = url::Url::parse(&super::super::issuer(service, headers))
        .map_err(|_| FlowError::internal())?;
    Ok(crate::PasskeyConfig {
        rp_id: state
            .config
            .proof_of_presence
            .rp_id
            .clone()
            .or_else(|| parsed.host_str().map(str::to_owned)),
        origins: Some(if state.config.proof_of_presence.origins.is_empty() {
            vec![parsed.origin().ascii_serialization()]
        } else {
            state.config.proof_of_presence.origins.clone()
        }),
        ..crate::PasskeyConfig::default()
    })
}
