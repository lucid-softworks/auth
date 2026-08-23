use super::TwoFactorError;
use crate::{
    AuthError, AuthService,
    axum::http::{auth_error, serialize_cookie, with_cookie},
};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub(super) fn set_plugin_cookie(
    service: &AuthService,
    suffix: &str,
    value: &str,
    max_age: i64,
    response: impl IntoResponse,
) -> Response {
    let cookie = service.plugin_cookie(suffix);
    with_cookie(
        response,
        serialize_cookie(&cookie, &service.signed_cookie_value(value), Some(max_age)),
    )
}

pub(super) fn expire_plugin_cookie(
    service: &AuthService,
    suffix: &str,
    response: impl IntoResponse,
) -> Response {
    let cookie = service.plugin_cookie(suffix);
    with_cookie(response, serialize_cookie(&cookie, "", Some(0)))
}

pub(super) fn verification_error(service: &AuthService, error: AuthError) -> Response {
    let expire = matches!(&error, AuthError::TwoFactor(TwoFactorError::InvalidCookie));
    expire_challenge_if(service, error, expire)
}

pub(super) fn challenge_verification_error(service: &AuthService, error: AuthError) -> Response {
    let expire = matches!(
        &error,
        AuthError::TwoFactor(TwoFactorError::InvalidCookie | TwoFactorError::TooManyAttempts)
    );
    expire_challenge_if(service, error, expire)
}

fn expire_challenge_if(service: &AuthService, error: AuthError, expire: bool) -> Response {
    let response = auth_error(error);
    if expire {
        expire_plugin_cookie(service, "two_factor", response)
    } else {
        response
    }
}

pub(crate) fn two_factor_error(error: TwoFactorError) -> Response {
    let (status, code, message) = match error {
        TwoFactorError::OtpNotEnabled => (
            StatusCode::BAD_REQUEST,
            "OTP_NOT_ENABLED",
            "OTP not enabled",
        ),
        TwoFactorError::OtpNotConfigured => (
            StatusCode::BAD_REQUEST,
            "OTP_NOT_CONFIGURED",
            "OTP is not available",
        ),
        TwoFactorError::OtpExpired => (
            StatusCode::BAD_REQUEST,
            "OTP_HAS_EXPIRED",
            "OTP has expired",
        ),
        TwoFactorError::TotpNotEnabled => (
            StatusCode::BAD_REQUEST,
            "TOTP_NOT_ENABLED",
            "TOTP not enabled",
        ),
        TwoFactorError::TotpNotConfigured => (
            StatusCode::BAD_REQUEST,
            "TOTP_NOT_CONFIGURED",
            "TOTP is not available",
        ),
        TwoFactorError::NotEnabled => (
            StatusCode::BAD_REQUEST,
            "TWO_FACTOR_NOT_ENABLED",
            "Two factor isn't enabled",
        ),
        TwoFactorError::BackupCodesNotEnabled => (
            StatusCode::BAD_REQUEST,
            "BACKUP_CODES_NOT_ENABLED",
            "Backup codes aren't enabled",
        ),
        TwoFactorError::InvalidBackupCode => (
            StatusCode::UNAUTHORIZED,
            "INVALID_BACKUP_CODE",
            "Invalid backup code",
        ),
        TwoFactorError::InvalidCode => (StatusCode::UNAUTHORIZED, "INVALID_CODE", "Invalid code"),
        TwoFactorError::TooManyAttempts => (
            StatusCode::BAD_REQUEST,
            "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
            "Too many attempts. Please request a new code.",
        ),
        TwoFactorError::AccountLocked => (
            StatusCode::TOO_MANY_REQUESTS,
            "ACCOUNT_TEMPORARILY_LOCKED",
            "Too many failed verification attempts. Your account is temporarily locked. Please try again later.",
        ),
        TwoFactorError::InvalidCookie => (
            StatusCode::UNAUTHORIZED,
            "INVALID_TWO_FACTOR_COOKIE",
            "Invalid two factor cookie",
        ),
        TwoFactorError::BackupCodeConflict => (
            StatusCode::CONFLICT,
            "FAILED_TO_VERIFY_BACKUP_CODE",
            "Failed to verify backup code. Please try again.",
        ),
    };
    (
        status,
        Json(crate::protocol::better_auth::ErrorResponse { code, message }),
    )
        .into_response()
}
