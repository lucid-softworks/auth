/// Better Auth username-plugin errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UsernameError {
    #[error("Invalid username or password")]
    InvalidUsernameOrPassword,
    #[error("Email not verified")]
    EmailNotVerified,
    #[error("Username is already taken. Please try another.")]
    AlreadyTaken,
    #[error("Username is too short")]
    TooShort,
    #[error("Username is too long")]
    TooLong,
    #[error("Username is invalid")]
    Invalid,
    #[error("Display username is invalid")]
    InvalidDisplayUsername,
    #[error("Username cannot be updated")]
    Immutable,
}

#[cfg(feature = "axum")]
pub(crate) fn http_error(
    error: crate::AuthError,
    validation_status: axum::http::StatusCode,
) -> axum::response::Response {
    use axum::{Json, response::IntoResponse};
    let crate::AuthError::Username(error) = error else {
        return crate::axum::http::auth_error(error);
    };
    let (status, code, message) = match error {
        UsernameError::InvalidUsernameOrPassword => (
            axum::http::StatusCode::UNAUTHORIZED,
            "INVALID_USERNAME_OR_PASSWORD",
            "Invalid username or password",
        ),
        UsernameError::EmailNotVerified => (
            axum::http::StatusCode::FORBIDDEN,
            "EMAIL_NOT_VERIFIED",
            "Email not verified",
        ),
        UsernameError::AlreadyTaken => (
            validation_status,
            "USERNAME_IS_ALREADY_TAKEN",
            "Username is already taken. Please try another.",
        ),
        UsernameError::TooShort => (
            validation_status,
            "USERNAME_TOO_SHORT",
            "Username is too short",
        ),
        UsernameError::TooLong => (
            validation_status,
            "USERNAME_TOO_LONG",
            "Username is too long",
        ),
        UsernameError::Invalid => (validation_status, "INVALID_USERNAME", "Username is invalid"),
        UsernameError::InvalidDisplayUsername => (
            validation_status,
            "INVALID_DISPLAY_USERNAME",
            "Display username is invalid",
        ),
        UsernameError::Immutable => (
            validation_status,
            "USERNAME_IS_IMMUTABLE",
            "Username cannot be updated",
        ),
    };
    (
        status,
        Json(crate::protocol::better_auth::ErrorResponse { code, message }),
    )
        .into_response()
}
