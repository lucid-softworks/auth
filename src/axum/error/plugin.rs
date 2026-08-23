use crate::{AuthError, protocol::better_auth::ErrorResponse};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub(super) fn response(error: &AuthError) -> Option<Response> {
    match error {
        AuthError::ApiKey(error) => Some(crate::api_key::api_key_error(error)),
        AuthError::TwoFactor(error) => Some(crate::two_factor::axum::two_factor_error(*error)),
        AuthError::StepUp(error) => {
            let details = match error {
                crate::StepUpError::RecoveryCodesNotEnabled => (
                    StatusCode::BAD_REQUEST,
                    "BACKUP_CODES_NOT_ENABLED",
                    "Recovery codes are not enabled for this account",
                ),
                crate::StepUpError::InvalidRecoveryCode => (
                    StatusCode::UNAUTHORIZED,
                    "INVALID_BACKUP_CODE",
                    "The recovery code is invalid",
                ),
            };
            let (status, code, message) = details;
            Some((status, Json(ErrorResponse { code, message })).into_response())
        }
        _ => None,
    }
}
