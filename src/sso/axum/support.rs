use crate::{AuthService, SessionWithUser};
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::json;

pub(super) async fn required_session(
    service: &AuthService,
    headers: &HeaderMap,
) -> Result<SessionWithUser, Box<Response>> {
    crate::axum::http::current_session(service, headers)
        .await
        .ok_or_else(|| Box::new(error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized")))
}

pub(super) fn error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> Response {
    crate::axum::api_error_with_body(
        status,
        json!({"code": code, "message": message.into()}),
    )
}

pub(super) fn storage(error: super::super::SsoStoreError) -> Response {
    tracing::error!(error = %error, "SSO provider storage failed");
    self::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        "Failed to read SSO providers",
    )
}
