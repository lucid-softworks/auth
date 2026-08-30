use crate::AuthError;
use axum::http::StatusCode;

pub(super) type ErrorDetails = (StatusCode, &'static str, &'static str);

pub(super) fn is_passkey_error(error: &AuthError) -> bool {
    matches!(
        error,
        AuthError::PasskeyNotFound
            | AuthError::PasskeyAuthenticationNotFound
            | AuthError::LastPasskey
            | AuthError::PasskeyChallengeExpired
            | AuthError::PasskeyVerificationFailed
            | AuthError::PasskeyOriginMissing
            | AuthError::PasskeyRegistrationFailed
            | AuthError::PasskeySessionRequired
            | AuthError::PasskeyRegistrationForbidden
            | AuthError::PasskeyResolverRequired
            | AuthError::PasskeyResolvedUserInvalid
            | AuthError::CredentialAlreadyRegistered
    )
}

pub(super) fn is_delete_user_error(error: &AuthError) -> bool {
    matches!(
        error,
        AuthError::SessionExpired
            | AuthError::InvalidDeleteUserToken
            | AuthError::DeleteUserInfoNotFound
    )
}

pub(super) fn delete_user_error_details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::SessionExpired => (
            StatusCode::BAD_REQUEST,
            "SESSION_EXPIRED",
            "Session expired. Re-authenticate to perform this action.",
        ),
        AuthError::InvalidDeleteUserToken => {
            (StatusCode::NOT_FOUND, "INVALID_TOKEN", "Invalid token")
        }
        _ => (
            StatusCode::NOT_FOUND,
            "FAILED_TO_GET_USER_INFO",
            "Failed to get user info",
        ),
    }
}

pub(super) fn request_security_error_details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::InvalidOrigin => (
            StatusCode::FORBIDDEN,
            "INVALID_ORIGIN",
            "The request origin is not trusted",
        ),
        AuthError::MissingOrigin => (
            StatusCode::FORBIDDEN,
            "MISSING_OR_NULL_ORIGIN",
            "The request origin is missing or null",
        ),
        AuthError::InvalidCallbackUrl => (
            StatusCode::FORBIDDEN,
            "INVALID_CALLBACK_URL",
            "The callback URL is not trusted",
        ),
        AuthError::InvalidRedirectUrl => (
            StatusCode::FORBIDDEN,
            "INVALID_REDIRECT_URL",
            "The redirect URL is not trusted",
        ),
        AuthError::InvalidErrorCallbackUrl => (
            StatusCode::FORBIDDEN,
            "INVALID_ERROR_CALLBACK_URL",
            "The error callback URL is not trusted",
        ),
        AuthError::InvalidNewUserCallbackUrl => (
            StatusCode::FORBIDDEN,
            "INVALID_NEW_USER_CALLBACK_URL",
            "The new-user callback URL is not trusted",
        ),
        _ => (
            StatusCode::FORBIDDEN,
            "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED",
            "Cross-site navigation login is blocked",
        ),
    }
}

pub(super) fn access_error_details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::Forbidden => (
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "You do not have permission to perform this action",
        ),
        AuthError::SessionNotFresh => (
            StatusCode::FORBIDDEN,
            "SESSION_NOT_FRESH",
            "Session is not fresh",
        ),
        AuthError::StepUpRequired => (
            StatusCode::FORBIDDEN,
            "STEP_UP_REQUIRED",
            "Verify a passkey or recovery code before performing this action",
        ),
        AuthError::NotFound => (
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "The requested authentication resource was not found",
        ),
        AuthError::UserAlreadyExists => (
            StatusCode::BAD_REQUEST,
            "USER_ALREADY_EXISTS",
            "A user with that username or email already exists",
        ),
        AuthError::UserAlreadyExistsEmail => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
            "User already exists. Use another email.",
        ),
        AuthError::LastOwner => (
            StatusCode::CONFLICT,
            "LAST_OWNER",
            "The final owner account cannot be removed or disabled",
        ),
        AuthError::InvalidGuestGrant => (
            StatusCode::UNAUTHORIZED,
            "INVALID_GUEST_GRANT",
            "The guest grant is invalid, expired, exhausted, or revoked",
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "The authentication request is invalid",
        ),
    }
}

pub(super) fn password_error_details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::CredentialAccountNotFound => (
            StatusCode::BAD_REQUEST,
            "CREDENTIAL_ACCOUNT_NOT_FOUND",
            "The credential account was not found",
        ),
        AuthError::InvalidPassword => (
            StatusCode::BAD_REQUEST,
            "INVALID_PASSWORD",
            "Invalid password",
        ),
        AuthError::PasswordTooShort => (
            StatusCode::BAD_REQUEST,
            "PASSWORD_TOO_SHORT",
            "Password too short",
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            "PASSWORD_TOO_LONG",
            "Password too long",
        ),
    }
}

pub(super) fn passkey_error_details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::PasskeyNotFound => (
            StatusCode::NOT_FOUND,
            "PASSKEY_NOT_FOUND",
            "Passkey not found",
        ),
        AuthError::PasskeyAuthenticationNotFound => (
            StatusCode::UNAUTHORIZED,
            "PASSKEY_NOT_FOUND",
            "Passkey not found",
        ),
        AuthError::LastPasskey => (
            StatusCode::CONFLICT,
            "LAST_PASSKEY",
            "An MFA-required account must keep at least one passkey",
        ),
        AuthError::PasskeyChallengeExpired => (
            StatusCode::BAD_REQUEST,
            "CHALLENGE_NOT_FOUND",
            "Challenge not found",
        ),
        AuthError::PasskeyVerificationFailed => (
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_FAILED",
            "Authentication failed",
        ),
        AuthError::PasskeyOriginMissing => {
            (StatusCode::BAD_REQUEST, "BAD_REQUEST", "origin missing")
        }
        AuthError::PasskeyRegistrationFailed => (
            StatusCode::BAD_REQUEST,
            "FAILED_TO_VERIFY_REGISTRATION",
            "Failed to verify registration",
        ),
        AuthError::PasskeySessionRequired => (
            StatusCode::UNAUTHORIZED,
            "SESSION_REQUIRED",
            "Passkey registration requires an authenticated session",
        ),
        AuthError::PasskeyRegistrationForbidden => (
            StatusCode::UNAUTHORIZED,
            "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
            "You are not allowed to register this passkey",
        ),
        AuthError::PasskeyResolverRequired => (
            StatusCode::BAD_REQUEST,
            "RESOLVE_USER_REQUIRED",
            "Passkey registration requires either an authenticated session or a resolveUser callback when requireSession is false",
        ),
        AuthError::PasskeyResolvedUserInvalid => (
            StatusCode::BAD_REQUEST,
            "RESOLVED_USER_INVALID",
            "Resolved user is invalid",
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            "PREVIOUSLY_REGISTERED",
            "Previously registered",
        ),
    }
}
