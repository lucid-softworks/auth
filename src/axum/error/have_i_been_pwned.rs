use crate::AuthError;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub(super) fn response(error: &AuthError) -> Option<Response> {
    match error {
        AuthError::PasswordCompromised(message) => Some(super::dynamic_error(
            StatusCode::BAD_REQUEST,
            crate::PASSWORD_COMPROMISED,
            message,
        )),
        AuthError::PasswordCheckStatus(status) => Some(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "message": format!("Failed to check password. Status: {status}")
                })),
            )
                .into_response(),
        ),
        AuthError::PasswordCheckUnavailable => Some(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "message": "Failed to check password. Please try again later."
                })),
            )
                .into_response(),
        ),
        _ => None,
    }
}
