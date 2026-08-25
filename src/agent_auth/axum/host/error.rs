use crate::AuthError;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

pub(super) fn result_response(result: Result<Value, HostError>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(super) fn store_error(_: AuthError) -> HostError {
    HostError::internal()
}

#[derive(Debug)]
pub(super) struct HostError {
    pub(super) status: StatusCode,
    pub(super) code: &'static str,
    pub(super) message: String,
    pub(super) extra: Option<Value>,
}

impl HostError {
    pub(super) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            extra: None,
        }
    }

    pub(super) fn with_extra(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        extra: Value,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            extra: Some(extra),
        }
    }

    pub(super) fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
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
            StatusCode::BAD_REQUEST,
            "invalid_public_key",
            "Public key is invalid or malformed",
        )
    }

    pub(super) fn host_not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "host_not_found", "Host not found")
    }

    pub(super) fn agent_not_found() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "agent_not_found",
            "Agent not found",
        )
    }

    pub(super) fn host_revoked() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "host_revoked",
            "Host has been revoked",
        )
    }

    pub(super) fn host_already_linked() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "host_already_linked",
            "Host is already linked to a different user",
        )
    }

    pub(super) fn not_pending_enrollment() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "host_not_pending_enrollment",
            "Host is not in a pending enrollment state",
        )
    }

    pub(super) fn enrollment_token_invalid() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "enrollment_token_invalid",
            "Enrollment token is invalid",
        )
    }

    pub(super) fn enrollment_token_expired() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "enrollment_token_expired",
            "Enrollment token has expired",
        )
    }

    pub(super) fn unauthorized() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "unauthorized",
            "Caller is not authorized for this operation",
        )
    }

    pub(super) fn unauthorized_session() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Authentication required",
        )
    }

    pub(super) fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Server-side failure",
        )
    }
}

impl IntoResponse for HostError {
    fn into_response(self) -> Response {
        let mut body = serde_json::Map::from_iter([
            ("error".into(), json!(self.code)),
            ("message".into(), json!(self.message)),
        ]);
        if let Some(Value::Object(extra)) = self.extra {
            body.extend(extra);
        }
        (self.status, Json(Value::Object(body))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_upstream_error_envelope() {
        let response = HostError::with_extra(
            StatusCode::BAD_REQUEST,
            "invalid_capabilities",
            "invalid",
            json!({"invalid_capabilities":["missing"]}),
        )
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
