use crate::{AuthError, protocol::better_auth::ErrorResponse};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

mod admin;
mod anonymous;
mod credential;
mod have_i_been_pwned;
mod oauth;
mod plugin;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ApiErrorResponse;

pub(crate) fn auth_error(error: AuthError) -> Response {
    marked(auth_error_inner(error))
}

/// Builds a Better Auth `APIError` response for a native plugin endpoint.
///
/// The internal marker lets compatible after hooks distinguish API errors
/// from arbitrary JSON responses with `code` and `message` fields.
pub fn api_error(
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
) -> Response {
    marked(
        (
            status,
            Json(OwnedErrorResponse {
                code: code.into(),
                message: message.into(),
            }),
        )
            .into_response(),
    )
}

/// Builds a marked Better Auth `APIError` response with a caller-owned body.
///
/// This is useful for plugin errors that carry fields in addition to `code`
/// and `message`; compatible after hooks can recognize the response without
/// mistaking ordinary JSON for an API error.
pub fn api_error_with_body(status: StatusCode, body: serde_json::Value) -> Response {
    marked((status, Json(body)).into_response())
}

fn marked(mut response: Response) -> Response {
    response.extensions_mut().insert(ApiErrorResponse);
    response
}

fn auth_error_inner(error: AuthError) -> Response {
    if let Some(response) = plugin::response(&error) {
        return response;
    }
    if let Some(response) = oauth::response(&error) {
        return response;
    }
    if let Some(response) = have_i_been_pwned::response(&error) {
        return response;
    }
    if let AuthError::AccountDisabled(message) = &error {
        return (
            StatusCode::FORBIDDEN,
            Json(DynamicErrorResponse {
                code: "BANNED_USER",
                message,
            }),
        )
            .into_response();
    }
    if let AuthError::InvalidRequest(message) = &error {
        return dynamic_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", message);
    }
    let (status, code, message) = match &error {
        error if credential::is_error(error) => credential::details(error),
        AuthError::RateLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            "TOO_MANY_REQUESTS",
            "Too many sign-in attempts",
        ),
        error if anonymous::is_error(error) => anonymous::details(error),
        AuthError::Forbidden
        | AuthError::SessionNotFresh
        | AuthError::StepUpRequired
        | AuthError::NotFound
        | AuthError::UserAlreadyExists
        | AuthError::UserAlreadyExistsEmail
        | AuthError::LastOwner
        | AuthError::InvalidGuestGrant => access_error_details(&error),
        AuthError::CredentialAccountNotFound
        | AuthError::InvalidPassword
        | AuthError::PasswordTooShort
        | AuthError::PasswordTooLong => password_error_details(&error),
        error if is_passkey_error(error) => passkey_error_details(error),
        AuthError::Username(_) => {
            return crate::username::error::http_error(error, StatusCode::BAD_REQUEST);
        }
        error if is_delete_user_error(error) => delete_user_error_details(error),
        AuthError::InvalidSession => (
            StatusCode::UNAUTHORIZED,
            "INVALID_SESSION",
            "The session is invalid or expired",
        ),
        AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized"),
        AuthError::InvalidOrigin
        | AuthError::MissingOrigin
        | AuthError::InvalidCallbackUrl
        | AuthError::InvalidRedirectUrl
        | AuthError::InvalidErrorCallbackUrl
        | AuthError::InvalidNewUserCallbackUrl
        | AuthError::CrossSiteNavigationLogin => request_security_error_details(&error),
        error if oauth::is_error(error) => oauth::details(error),
        AuthError::InvalidConfiguration(_) | AuthError::Storage(_) | AuthError::Worker => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "Authentication failed",
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "Authentication failed",
        ),
    };
    (status, Json(ErrorResponse { code, message })).into_response()
}

pub(super) fn dynamic_error(status: StatusCode, code: &'static str, message: &str) -> Response {
    (status, Json(DynamicErrorResponse { code, message })).into_response()
}

#[derive(Serialize)]
struct DynamicErrorResponse<'a> {
    code: &'static str,
    message: &'a str,
}

#[derive(Serialize)]
struct OwnedErrorResponse {
    code: String,
    message: String,
}

fn is_passkey_error(error: &AuthError) -> bool {
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

type ErrorDetails = (StatusCode, &'static str, &'static str);

fn is_delete_user_error(error: &AuthError) -> bool {
    matches!(
        error,
        AuthError::SessionExpired
            | AuthError::InvalidDeleteUserToken
            | AuthError::DeleteUserInfoNotFound
    )
}

fn delete_user_error_details(error: &AuthError) -> ErrorDetails {
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

fn request_security_error_details(error: &AuthError) -> ErrorDetails {
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

fn access_error_details(error: &AuthError) -> ErrorDetails {
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

fn password_error_details(error: &AuthError) -> ErrorDetails {
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

fn passkey_error_details(error: &AuthError) -> ErrorDetails {
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
