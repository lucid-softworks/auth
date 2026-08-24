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
        AuthError::OperatorSecurity(error) => {
            let details = match error {
                crate::OperatorSecurityError::TemporaryPasswordRequired => (
                    StatusCode::FORBIDDEN,
                    "TEMPORARY_PASSWORD_REPLACEMENT_REQUIRED",
                    "The temporary password must be replaced",
                ),
                crate::OperatorSecurityError::SoleOwnerRecoveryUnavailable => (
                    StatusCode::FORBIDDEN,
                    "SOLE_OWNER_RECOVERY_UNAVAILABLE",
                    "Local recovery requires the named account to be the sole owner",
                ),
            };
            let (status, code, message) = details;
            Some((status, Json(ErrorResponse { code, message })).into_response())
        }
        AuthError::Admin(error) => {
            let (status, code, message) = super::admin::details(*error);
            Some((status, Json(ErrorResponse { code, message })).into_response())
        }
        AuthError::Organization(error) => {
            let status = match error.status {
                crate::OrganizationErrorStatus::BadRequest => StatusCode::BAD_REQUEST,
                crate::OrganizationErrorStatus::Unauthorized => StatusCode::UNAUTHORIZED,
                crate::OrganizationErrorStatus::Forbidden => StatusCode::FORBIDDEN,
                crate::OrganizationErrorStatus::NotFound => StatusCode::NOT_FOUND,
                crate::OrganizationErrorStatus::InternalServerError => {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            };
            Some(super::dynamic_error(status, error.code, &error.message))
        }
        _ => None,
    }
}
