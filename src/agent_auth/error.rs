use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

macro_rules! error_codes {
    ($($variant:ident => ($code:literal, $message:literal),)+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum AgentAuthErrorCode { $($variant,)+ }

        impl AgentAuthErrorCode {
            pub const fn code(self) -> &'static str {
                match self { $(Self::$variant => $code,)+ }
            }

            pub const fn message(self) -> &'static str {
                match self { $(Self::$variant => $message,)+ }
            }
        }

        impl Serialize for AgentAuthErrorCode {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.code())
            }
        }
    };
}

error_codes! {
    InvalidRequest => ("invalid_request", "Malformed request, missing required fields, or invalid parameter types"),
    InvalidJwt => ("invalid_jwt", "JWT is invalid, expired, or signature failed"),
    AgentRevoked => ("agent_revoked", "Agent has been revoked"),
    GrantRevoked => ("grant_revoked", "Capability grant has been revoked"),
    AgentExpired => ("agent_expired", "Agent session has expired"),
    AbsoluteLifetimeExceeded => ("absolute_lifetime_exceeded", "Agent's absolute lifetime has elapsed"),
    AgentPending => ("agent_pending", "Agent is still pending approval"),
    AgentRejected => ("agent_rejected", "Agent registration was denied"),
    AgentClaimed => ("agent_claimed", "Agent has been claimed and is no longer active"),
    AgentNotExpired => ("agent_not_expired", "Agent is not in an expired state"),
    HostRevoked => ("host_revoked", "Host has been revoked"),
    HostPending => ("host_pending", "Host is still pending approval"),
    Unauthorized => ("unauthorized", "Caller is not authorized for this operation"),
    RateLimited => ("rate_limited", "Too many requests"),
    InternalError => ("internal_error", "Server-side failure"),
    UnsupportedMode => ("unsupported_mode", "Requested mode is not supported by this server"),
    UnsupportedAlgorithm => ("unsupported_algorithm", "Key algorithm is not in the server's supported set"),
    InvalidCapabilities => ("invalid_capabilities", "One or more requested capability names don't exist or are blocked"),
    AgentExists => ("agent_exists", "An agent with this public key is already registered"),
    AlreadyGranted => ("already_granted", "All requested capabilities are already granted"),
    CapabilityNotGranted => ("capability_not_granted", "Agent does not have an active grant for this capability"),
    LimitExceeded => ("limit_exceeded", "Request exceeds the agent's limits for this capability"),
    CapabilityBlocked => ("capability_blocked", "One or more requested capabilities are blocked by server policy"),
    AgentNotFound => ("agent_not_found", "Agent not found"),
    HostNotFound => ("host_not_found", "Host not found"),
    UnauthorizedSession => ("unauthorized", "Authentication required"),
    InvalidPublicKey => ("invalid_public_key", "Public key is invalid or malformed"),
    JwtReplay => ("jti_replay", "JWT has already been used"),
    RequestBindingMismatch => ("request_binding_mismatch", "Request binding does not match the JWT"),
    HostExpired => ("host_expired", "Host has expired"),
    HostAlreadyLinked => ("host_already_linked", "Host is already linked to a different user"),
    HostNotPendingEnrollment => ("host_not_pending_enrollment", "Host is not in a pending enrollment state"),
    DynamicHostRegistrationDisabled => ("dynamic_host_registration_disabled", "Dynamic host registration is disabled. Enable it by passing `allowDynamicHostRegistration: true` to `agentAuth({...})`, or pre-enroll your host via `POST /host/create` + `POST /host/enroll`. See https://agent-auth-protocol.com/docs/host#enrollment"),
    EnrollmentTokenInvalid => ("enrollment_token_invalid", "Enrollment token is invalid"),
    EnrollmentTokenExpired => ("enrollment_token_expired", "Enrollment token has expired"),
    CapabilityRequestNotFound => ("capability_request_not_found", "Capability request not found"),
    CapabilityRequestAlreadyResolved => ("capability_request_already_resolved", "Capability request has already been resolved"),
    CapabilityRequestOwnerMismatch => ("capability_request_owner_mismatch", "Capability request does not belong to this user"),
    FreshSessionRequired => ("fresh_session_required", "A fresh authentication session is required for this operation"),
    CapabilityDenied => ("capability_denied", "Capability request was denied"),
    AgentLimitReached => ("agent_limit_reached", "Maximum number of active agents per user reached"),
    AutonomousOwnerRequired => ("autonomous_owner_required", "Autonomous agents require an owner to be resolved"),
    CibaNotFound => ("ciba_not_found", "CIBA authentication request not found"),
    CibaExpired => ("ciba_expired", "CIBA authentication request has expired"),
    CibaAlreadyResolved => ("ciba_already_resolved", "CIBA authentication request has already been resolved"),
    CibaSlowDown => ("slow_down", "Polling too frequently, slow down"),
    UnknownCapabilities => ("unknown_capabilities", "One or more capability names are not recognized"),
    CapabilityNotFound => ("capability_not_found", "Capability does not exist"),
    AuthRequiredForCapabilities => ("authentication_required", "This server requires authentication to list capabilities. Connect an agent first, then retry with the agent JWT."),
    ConstraintViolated => ("constraint_violated", "One or more capability constraints were violated"),
    ExecuteNotConfigured => ("execute_not_configured", "Server has not configured a capability execution handler"),
    UnknownConstraintOperator => ("unknown_constraint_operator", "Constraint contains an unrecognized operator"),
    InvalidUserCode => ("invalid_user_code", "The user code is missing or does not match"),
    ApprovalExpired => ("approval_expired", "The approval request has expired"),
    WebauthnNotEnrolled => ("webauthn_not_enrolled", "No passkeys registered. Register a passkey before approving capabilities that require proof of physical presence."),
    WebauthnRequired => ("webauthn_required", "This approval requires proof of physical presence. Complete the WebAuthn challenge."),
    WebauthnVerificationFailed => ("webauthn_verification_failed", "WebAuthn verification failed"),
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentAuthApiError {
    pub status: u16,
    pub code: AgentAuthErrorCode,
    pub message: String,
    pub headers: BTreeMap<String, String>,
    pub extra: Map<String, Value>,
}

impl AgentAuthApiError {
    pub fn new(status: u16, code: AgentAuthErrorCode) -> Self {
        Self {
            status,
            code,
            message: code.message().to_owned(),
            headers: BTreeMap::new(),
            extra: Map::new(),
        }
    }

    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    pub fn body(&self) -> Value {
        let mut body = Map::from_iter([
            ("error".into(), Value::String(self.code.code().into())),
            ("message".into(), Value::String(self.message.clone())),
        ]);
        body.extend(self.extra.clone());
        Value::Object(body)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AgentAuthChallengeError {
    #[error("Agent Auth base URL is invalid")]
    InvalidBaseUrl,
}

pub fn agent_auth_challenge(base_url: &str) -> Result<String, AgentAuthChallengeError> {
    let parsed = url::Url::parse(base_url).map_err(|_| AgentAuthChallengeError::InvalidBaseUrl)?;
    let origin = parsed.origin().ascii_serialization();
    Ok(format!(
        "AgentAuth discovery=\"{origin}/.well-known/agent-configuration\""
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_codes_messages_and_challenge_are_stable() {
        assert_eq!(AgentAuthErrorCode::JwtReplay.code(), "jti_replay");
        assert_eq!(
            AgentAuthErrorCode::ExecuteNotConfigured.message(),
            "Server has not configured a capability execution handler"
        );
        assert_eq!(
            agent_auth_challenge("https://provider.example/api/auth/").unwrap(),
            "AgentAuth discovery=\"https://provider.example/.well-known/agent-configuration\""
        );
        assert_eq!(
            AgentAuthApiError::new(403, AgentAuthErrorCode::CapabilityBlocked).body(),
            serde_json::json!({
                "error": "capability_blocked",
                "message": "One or more requested capabilities are blocked by server policy"
            })
        );
    }
}
