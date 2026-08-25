use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;

use crate::{AuthError, agent_auth::jwt::AgentJwtError};

#[derive(Debug)]
pub(in crate::agent_auth::axum) struct AgentAuthenticationError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl AgentAuthenticationError {
    fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }

    pub(super) fn from_jwt(error: AgentJwtError) -> Self {
        match error {
            AgentJwtError::Replay => Self::new(
                StatusCode::UNAUTHORIZED,
                "jti_replay",
                "JWT has already been used",
            ),
            AgentJwtError::RequestBindingMismatch => Self::new(
                StatusCode::UNAUTHORIZED,
                "request_binding_mismatch",
                "Request binding does not match the JWT",
            ),
            AgentJwtError::InvalidPublicKey | AgentJwtError::UnsupportedAlgorithm => {
                Self::invalid_public_key()
            }
            _ => Self::invalid_jwt(),
        }
    }

    pub(super) fn invalid_jwt() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_jwt",
            "JWT is invalid, expired, or signature failed",
        )
    }

    pub(super) fn invalid_public_key() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_public_key",
            "Public key is invalid or malformed",
        )
    }

    pub(super) fn agent_not_found() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "agent_not_found",
            "Agent not found",
        )
    }

    pub(super) fn agent_revoked() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "agent_revoked",
            "Agent has been revoked",
        )
    }

    pub(super) fn agent_claimed() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "agent_claimed",
            "Agent has been claimed and is no longer active",
        )
    }

    pub(super) fn agent_pending() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "agent_pending",
            "Agent is still pending approval",
        )
    }

    pub(super) fn agent_rejected() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "agent_rejected",
            "Agent registration was denied",
        )
    }

    pub(super) fn agent_expired() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "agent_expired",
            "Agent session has expired",
        )
    }

    pub(super) fn absolute_lifetime() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "absolute_lifetime_exceeded",
            "Agent's absolute lifetime has elapsed",
        )
    }

    pub(super) fn autonomous_owner_required() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "autonomous_owner_required",
            "Could not resolve a session user for this agent.",
        )
    }

    pub(super) fn storage(_error: AuthError) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Server-side failure",
        )
    }

    pub(super) fn into_response(self, discovery_origin: &str) -> axum::response::Response {
        let mut response = (
            self.status,
            Json(json!({"error": self.code, "message": self.message})),
        )
            .into_response();
        if self.status == StatusCode::UNAUTHORIZED
            && let Ok(challenge) = format!(
                "AgentAuth discovery=\"{discovery_origin}/.well-known/agent-configuration\""
            )
            .parse()
        {
            response
                .headers_mut()
                .insert(axum::http::header::WWW_AUTHENTICATE, challenge);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_failures_map_to_exact_protocol_codes() {
        let replay = AgentAuthenticationError::from_jwt(AgentJwtError::Replay);
        assert_eq!(replay.code, "jti_replay");
        let binding = AgentAuthenticationError::from_jwt(AgentJwtError::RequestBindingMismatch);
        assert_eq!(binding.code, "request_binding_mismatch");
        let signature = AgentAuthenticationError::from_jwt(AgentJwtError::InvalidSignature);
        assert_eq!(signature.code, "invalid_jwt");
    }
}
