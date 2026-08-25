use crate::AuthError;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

#[derive(Debug)]
pub(super) struct AgentError {
    status: StatusCode,
    pub(super) code: &'static str,
    message: String,
    extra: Option<Value>,
}

impl AgentError {
    pub(super) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            extra: None,
        }
    }

    pub(super) fn bad(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub(super) fn unauthorized_session() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized_session",
            "No valid agent, host, or user session was found",
        )
    }

    pub(super) fn unauthorized() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "unauthorized",
            "Caller is not authorized for this operation",
        )
    }

    pub(super) fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "agent_not_found", "Agent not found")
    }

    pub(super) fn forbidden_status(status: crate::AgentStatus) -> Self {
        match status {
            crate::AgentStatus::Revoked => Self::new(
                StatusCode::FORBIDDEN,
                "agent_revoked",
                "Agent has been revoked",
            ),
            crate::AgentStatus::Rejected => Self::new(
                StatusCode::FORBIDDEN,
                "agent_rejected",
                "Agent registration was denied",
            ),
            crate::AgentStatus::Claimed => Self::new(
                StatusCode::FORBIDDEN,
                "agent_claimed",
                "Agent has been claimed and is no longer active",
            ),
            _ => Self::new(
                StatusCode::FORBIDDEN,
                "agent_pending",
                "Agent is still pending approval",
            ),
        }
    }

    pub(super) fn store(_: AuthError) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Server-side failure",
        )
    }

    pub(super) fn into_response(self) -> Response {
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

pub(super) fn response(result: Result<Value, AgentError>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_envelope_uses_error_and_message() {
        let response = AgentError::not_found().into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
