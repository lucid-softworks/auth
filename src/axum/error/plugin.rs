use crate::{AuthError, protocol::better_auth::ErrorResponse};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub(super) fn response(error: &AuthError) -> Option<Response> {
    match error {
        AuthError::ApiKey(error) => Some(crate::api_key::api_key_error(error)),
        AuthError::EmailOtp(error) => Some(email_otp_error(*error)),
        AuthError::PhoneNumber(error) => Some(phone_number_error(*error)),
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

fn phone_number_error(error: crate::PhoneNumberError) -> Response {
    use crate::PhoneNumberError as Error;
    let (status, code, message) = match error {
        Error::InvalidPhoneNumber => (
            StatusCode::BAD_REQUEST,
            "INVALID_PHONE_NUMBER",
            "Invalid phone number",
        ),
        Error::PhoneNumberExists => (
            StatusCode::BAD_REQUEST,
            "PHONE_NUMBER_EXIST",
            "Phone number already exists",
        ),
        Error::PhoneNumberNotRegistered => (
            StatusCode::BAD_REQUEST,
            "PHONE_NUMBER_NOT_EXIST",
            "phone number isn't registered",
        ),
        Error::InvalidPhoneNumberOrPassword => (
            StatusCode::UNAUTHORIZED,
            "INVALID_PHONE_NUMBER_OR_PASSWORD",
            "Invalid phone number or password",
        ),
        Error::UnexpectedSignIn => (
            StatusCode::UNAUTHORIZED,
            "UNEXPECTED_ERROR",
            "Unexpected error",
        ),
        Error::UnexpectedError => (
            StatusCode::BAD_REQUEST,
            "UNEXPECTED_ERROR",
            "Unexpected error",
        ),
        Error::OtpNotFound => (StatusCode::BAD_REQUEST, "OTP_NOT_FOUND", "OTP not found"),
        Error::OtpExpired => (StatusCode::BAD_REQUEST, "OTP_EXPIRED", "OTP expired"),
        Error::InvalidOtp => (StatusCode::BAD_REQUEST, "INVALID_OTP", "Invalid OTP"),
        Error::PhoneNumberNotVerified => (
            StatusCode::UNAUTHORIZED,
            "PHONE_NUMBER_NOT_VERIFIED",
            "Phone number not verified",
        ),
        Error::PhoneNumberCannotBeUpdated => (
            StatusCode::BAD_REQUEST,
            "PHONE_NUMBER_CANNOT_BE_UPDATED",
            "Phone number cannot be updated",
        ),
        Error::SendOtpNotImplemented => (
            StatusCode::NOT_IMPLEMENTED,
            "SEND_OTP_NOT_IMPLEMENTED",
            "sendOTP not implemented",
        ),
        Error::TooManyAttempts => (
            StatusCode::FORBIDDEN,
            "TOO_MANY_ATTEMPTS",
            "Too many attempts",
        ),
        Error::UserNotFound => (StatusCode::UNAUTHORIZED, "USER_NOT_FOUND", "User not found"),
        Error::FailedToUpdateUser => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "FAILED_TO_UPDATE_USER",
            "Failed to update user",
        ),
    };
    (status, Json(ErrorResponse { code, message })).into_response()
}

fn email_otp_error(error: crate::EmailOtpError) -> Response {
    use crate::EmailOtpError as Error;
    let (status, code, message) = match error {
        Error::InvalidOtp => (StatusCode::BAD_REQUEST, "INVALID_OTP", "Invalid OTP"),
        Error::OtpExpired => (StatusCode::BAD_REQUEST, "OTP_EXPIRED", "OTP expired"),
        Error::TooManyAttempts => (
            StatusCode::FORBIDDEN,
            "TOO_MANY_ATTEMPTS",
            "Too many attempts",
        ),
        Error::UserNotFound => (StatusCode::BAD_REQUEST, "USER_NOT_FOUND", "User not found"),
        Error::InvalidOtpType => (StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid OTP type"),
        Error::ChangeEmailDisabled => (
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Change email with OTP is disabled",
        ),
        Error::CurrentEmailOtpRequired => (
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "OTP is required to verify current email",
        ),
        Error::EmailIsSame => (StatusCode::BAD_REQUEST, "BAD_REQUEST", "Email is the same"),
        Error::EmailAlreadyInUse => (
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Email already in use",
        ),
        Error::HashedOtpUnavailable => (
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "OTP is hashed, cannot return the plain text OTP",
        ),
    };
    (status, Json(ErrorResponse { code, message })).into_response()
}
