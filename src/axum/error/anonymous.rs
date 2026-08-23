use super::ErrorDetails;
use crate::AuthError;
use axum::http::StatusCode;

pub(super) fn is_error(error: &AuthError) -> bool {
    matches!(
        error,
        AuthError::AnonymousInvalidEmail
            | AuthError::AnonymousUserCreationFailed
            | AuthError::AnonymousSessionCreationFailed
            | AuthError::AnonymousSignInAgain
            | AuthError::AnonymousUserDeletionFailed
            | AuthError::AnonymousUserSessionDeletionFailed
            | AuthError::UserIsNotAnonymous
            | AuthError::AnonymousUserDeletionDisabled
    )
}

pub(super) fn details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::AnonymousInvalidEmail => (
            StatusCode::BAD_REQUEST,
            "INVALID_EMAIL_FORMAT",
            "Email was not generated in a valid format",
        ),
        AuthError::AnonymousUserCreationFailed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "FAILED_TO_CREATE_USER",
            "Failed to create user",
        ),
        AuthError::AnonymousSessionCreationFailed => (
            StatusCode::BAD_REQUEST,
            "COULD_NOT_CREATE_SESSION",
            "Could not create session",
        ),
        AuthError::AnonymousSignInAgain => (
            StatusCode::BAD_REQUEST,
            "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
            "Anonymous users cannot sign in again anonymously",
        ),
        AuthError::AnonymousUserDeletionFailed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "FAILED_TO_DELETE_ANONYMOUS_USER",
            "Failed to delete anonymous user",
        ),
        AuthError::AnonymousUserSessionDeletionFailed => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS",
            "Failed to delete anonymous user sessions",
        ),
        AuthError::UserIsNotAnonymous => (
            StatusCode::FORBIDDEN,
            "USER_IS_NOT_ANONYMOUS",
            "User is not anonymous",
        ),
        AuthError::AnonymousUserDeletionDisabled => (
            StatusCode::BAD_REQUEST,
            "DELETE_ANONYMOUS_USER_DISABLED",
            "Deleting anonymous users is disabled",
        ),
        _ => unreachable!("anonymous error classifier and details must agree"),
    }
}
