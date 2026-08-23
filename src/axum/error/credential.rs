use super::ErrorDetails;
use crate::AuthError;
use axum::http::StatusCode;

pub(super) fn is_error(error: &AuthError) -> bool {
    matches!(
        error,
        AuthError::InvalidCredentials
            | AuthError::InvalidEmailOrPassword
            | AuthError::InvalidEmail
            | AuthError::EmailPasswordDisabled
            | AuthError::EmailPasswordSignUpDisabled
            | AuthError::EmailNotVerified
            | AuthError::VerificationEmailNotEnabled
            | AuthError::EmailMismatch
            | AuthError::EmailAlreadyVerified
            | AuthError::ChangeEmailDisabled
            | AuthError::EmailIsSame
            | AuthError::InvalidUser
            | AuthError::InvalidToken
            | AuthError::TokenExpired
            | AuthError::VerificationUserNotFound
            | AuthError::ResetPasswordDisabled
            | AuthError::InvalidPasswordResetToken
            | AuthError::PasswordResetUserNotFound
    )
}

pub(super) fn details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::InvalidCredentials => (
            StatusCode::UNAUTHORIZED,
            "INVALID_USERNAME_OR_PASSWORD",
            "Invalid username or password",
        ),
        AuthError::InvalidEmailOrPassword => (
            StatusCode::UNAUTHORIZED,
            "INVALID_EMAIL_OR_PASSWORD",
            "Invalid email or password",
        ),
        AuthError::InvalidEmail => (StatusCode::BAD_REQUEST, "INVALID_EMAIL", "Invalid email"),
        AuthError::EmailPasswordDisabled => (
            StatusCode::BAD_REQUEST,
            "EMAIL_PASSWORD_DISABLED",
            "Email and password is not enabled",
        ),
        AuthError::EmailPasswordSignUpDisabled => (
            StatusCode::BAD_REQUEST,
            "EMAIL_PASSWORD_SIGN_UP_DISABLED",
            "Email and password sign up is not enabled",
        ),
        AuthError::EmailNotVerified => (
            StatusCode::FORBIDDEN,
            "EMAIL_NOT_VERIFIED",
            "Email not verified",
        ),
        AuthError::VerificationEmailNotEnabled => (
            StatusCode::BAD_REQUEST,
            "VERIFICATION_EMAIL_NOT_ENABLED",
            "Verification email isn't enabled",
        ),
        AuthError::EmailMismatch => (StatusCode::BAD_REQUEST, "EMAIL_MISMATCH", "Email mismatch"),
        AuthError::EmailAlreadyVerified => (
            StatusCode::BAD_REQUEST,
            "EMAIL_ALREADY_VERIFIED",
            "Email is already verified",
        ),
        AuthError::ChangeEmailDisabled => (
            StatusCode::BAD_REQUEST,
            "CHANGE_EMAIL_DISABLED",
            "Change email is disabled",
        ),
        AuthError::EmailIsSame => (
            StatusCode::BAD_REQUEST,
            "EMAIL_IS_THE_SAME",
            "Email is the same",
        ),
        AuthError::InvalidUser => (StatusCode::UNAUTHORIZED, "INVALID_USER", "Invalid user"),
        AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "TOKEN_EXPIRED", "Token expired"),
        AuthError::VerificationUserNotFound => {
            (StatusCode::UNAUTHORIZED, "USER_NOT_FOUND", "User not found")
        }
        AuthError::ResetPasswordDisabled => (
            StatusCode::BAD_REQUEST,
            "RESET_PASSWORD_DISABLED",
            "Reset password isn't enabled",
        ),
        AuthError::InvalidPasswordResetToken => {
            (StatusCode::BAD_REQUEST, "INVALID_TOKEN", "Invalid token")
        }
        AuthError::PasswordResetUserNotFound => {
            (StatusCode::BAD_REQUEST, "USER_NOT_FOUND", "User not found")
        }
        _ => (StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Invalid token"),
    }
}
