use super::super::support;
use crate::{AuthService, CommetProviderError, PluginApiError, SessionWithUser};
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};

pub(super) async fn required_session(
    service: &AuthService,
    headers: &HeaderMap,
) -> Result<SessionWithUser, Box<Response>> {
    crate::axum::http::current_session(service, headers)
        .await
        .ok_or_else(|| {
            Box::new(support::coded(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Unauthorized",
            ))
        })
}

pub(super) fn provider_error(error: CommetProviderError, message: &'static str) -> Response {
    match error.into_api_error() {
        Ok(error) => api_error(error),
        Err(error) => {
            tracing::error!(error = %error, "Commet provider request failed");
            support::message(StatusCode::INTERNAL_SERVER_ERROR, message)
        }
    }
}

pub(super) fn api_error(error: PluginApiError) -> Response {
    support::message(
        StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        error.message,
    )
}

pub(super) fn validation(error: super::super::input::InputError) -> Response {
    support::coded(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", error.message())
}
