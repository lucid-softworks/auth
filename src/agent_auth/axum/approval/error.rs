use crate::{AgentAuthApiError, AgentAuthErrorCode, AuthError};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub(super) type Result<T> = std::result::Result<T, FlowError>;

pub(super) struct FlowError(pub(super) Box<AgentAuthApiError>);

impl FlowError {
    pub(super) fn code(status: StatusCode, code: AgentAuthErrorCode) -> Self {
        Self(Box::new(AgentAuthApiError::new(status.as_u16(), code)))
    }

    pub(super) fn message(
        status: StatusCode,
        code: AgentAuthErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self(Box::new(
            AgentAuthApiError::new(status.as_u16(), code).with_message(message),
        ))
    }

    pub(super) fn internal() -> Self {
        Self::code(
            StatusCode::INTERNAL_SERVER_ERROR,
            AgentAuthErrorCode::InternalError,
        )
    }

    pub(super) fn fresh_session(max_age: u64, session_age: u64) -> Self {
        let mut error = AgentAuthApiError::new(
            StatusCode::FORBIDDEN.as_u16(),
            AgentAuthErrorCode::FreshSessionRequired,
        )
        .with_message(
            "A fresh authentication session is required for this operation. Please re-authenticate and try again.",
        );
        error.extra.insert("max_age".into(), max_age.into());
        error.extra.insert("session_age".into(), session_age.into());
        Self(Box::new(error))
    }

    pub(super) fn with_extra(
        status: StatusCode,
        code: AgentAuthErrorCode,
        key: &str,
        value: serde_json::Value,
    ) -> Self {
        let mut error = AgentAuthApiError::new(status.as_u16(), code);
        error.extra.insert(key.into(), value);
        Self(Box::new(error))
    }
}

impl From<AuthError> for FlowError {
    fn from(_: AuthError) -> Self {
        Self::internal()
    }
}

impl IntoResponse for FlowError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self.0.body())).into_response()
    }
}

pub(super) fn response(result: Result<serde_json::Value>) -> Response {
    match result {
        Ok(body) => Json(body).into_response(),
        Err(error) => error.into_response(),
    }
}
