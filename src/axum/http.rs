use crate::{
    AuthError, AuthService, SessionWithUser,
    protocol::better_auth::{ErrorResponse, PASSKEY_CHALLENGE_COOKIE_NAME, SESSION_COOKIE_NAME},
};
use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

pub(super) async fn current_session(
    service: &AuthService,
    headers: &HeaderMap,
) -> Option<SessionWithUser> {
    let token = session_token(service, headers)?;
    service.session(&token).await.ok().flatten()
}

pub(super) fn challenge_token(service: &AuthService, headers: &HeaderMap) -> Option<String> {
    signed_cookie_token(service, headers, PASSKEY_CHALLENGE_COOKIE_NAME)
}

pub(super) fn with_challenge_cookie(
    service: &AuthService,
    token: &str,
    body: impl IntoResponse,
) -> Response {
    with_cookie(
        body,
        named_cookie(
            PASSKEY_CHALLENGE_COOKIE_NAME,
            &service.signed_cookie_value(token),
            300,
            service.cookie_secure(),
            true,
        ),
    )
}

pub(super) fn with_session_cookie(
    service: &AuthService,
    token: &str,
    remember_me: Option<bool>,
    body: impl IntoResponse,
) -> Response {
    let cookie = session_cookie(
        &service.signed_cookie_value(token),
        service.session_ttl().num_seconds(),
        service.cookie_secure(),
        remember_me != Some(false),
    );
    with_cookie(body, cookie)
}

pub(super) fn clear_session_cookie(service: &AuthService, body: impl IntoResponse) -> Response {
    with_cookie(body, session_cookie("", 0, service.cookie_secure(), true))
}

pub fn session_token(service: &AuthService, headers: &HeaderMap) -> Option<String> {
    signed_cookie_token(service, headers, SESSION_COOKIE_NAME)
}

fn signed_cookie_token(service: &AuthService, headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_value = headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|cookie| cookie.strip_prefix(&format!("{name}=")))?;
    service.verify_cookie_value(cookie_value)
}

pub(super) fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(512).collect())
}

fn session_cookie(value: &str, max_age_seconds: i64, secure: bool, persistent: bool) -> String {
    named_cookie(
        SESSION_COOKIE_NAME,
        value,
        max_age_seconds,
        secure,
        persistent,
    )
}

fn named_cookie(
    name: &str,
    value: &str,
    max_age_seconds: i64,
    secure: bool,
    persistent: bool,
) -> String {
    let mut cookie = format!("{name}={value}; HttpOnly; SameSite=Lax; Path=/");
    if persistent {
        cookie.push_str(&format!("; Max-Age={max_age_seconds}"));
    }
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn with_cookie(body: impl IntoResponse, cookie: String) -> Response {
    let mut response = body.into_response();
    match HeaderValue::from_str(&cookie) {
        Ok(value) => {
            response.headers_mut().insert(header::SET_COOKIE, value);
            response
        }
        Err(_) => auth_error(AuthError::InvalidConfiguration(
            "session cookie could not be encoded".into(),
        )),
    }
}

pub(super) fn auth_error(error: AuthError) -> Response {
    let (status, code, message) = match &error {
        AuthError::InvalidCredentials => (
            StatusCode::UNAUTHORIZED,
            "INVALID_USERNAME_OR_PASSWORD",
            "Invalid username or password",
        ),
        AuthError::RateLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            "TOO_MANY_REQUESTS",
            "Too many sign-in attempts",
        ),
        AuthError::AnonymousAccessDisabled => (
            StatusCode::FORBIDDEN,
            "ANONYMOUS_ACCESS_DISABLED",
            "Anonymous guest access is disabled",
        ),
        AuthError::AccountDisabled => (
            StatusCode::FORBIDDEN,
            "USER_BANNED",
            "The account is disabled",
        ),
        AuthError::Forbidden
        | AuthError::NotFound
        | AuthError::LastOwner
        | AuthError::InvalidGuestGrant
        | AuthError::InvalidRequest(_) => access_error_details(&error),
        AuthError::CredentialAccountNotFound
        | AuthError::InvalidPassword
        | AuthError::PasswordTooShort
        | AuthError::PasswordTooLong => password_error_details(&error),
        AuthError::PasskeyNotFound
        | AuthError::PasskeyDisabled
        | AuthError::PasskeyChallengeExpired
        | AuthError::PasskeyVerificationFailed
        | AuthError::CredentialAlreadyRegistered => passkey_error_details(&error),
        AuthError::InvalidSession => (
            StatusCode::UNAUTHORIZED,
            "INVALID_SESSION",
            "The session is invalid or expired",
        ),
        AuthError::InvalidConfiguration(_) | AuthError::Storage(_) | AuthError::Worker => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "Authentication failed",
        ),
    };
    (status, Json(ErrorResponse { code, message })).into_response()
}

type ErrorDetails = (StatusCode, &'static str, &'static str);

fn access_error_details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::Forbidden => (
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "You do not have permission to perform this action",
        ),
        AuthError::NotFound => (
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "The requested authentication resource was not found",
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
            "The current password is incorrect",
        ),
        AuthError::PasswordTooShort => (
            StatusCode::BAD_REQUEST,
            "PASSWORD_TOO_SHORT",
            "The new password must contain at least 8 characters",
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            "PASSWORD_TOO_LONG",
            "The new password must contain at most 128 characters",
        ),
    }
}

fn passkey_error_details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::PasskeyNotFound => (
            StatusCode::NOT_FOUND,
            "PASSKEY_NOT_FOUND",
            "The passkey was not found",
        ),
        AuthError::PasskeyDisabled => (
            StatusCode::NOT_IMPLEMENTED,
            "PASSKEY_NOT_CONFIGURED",
            "Passkey authentication is not configured",
        ),
        AuthError::PasskeyChallengeExpired => (
            StatusCode::BAD_REQUEST,
            "CHALLENGE_NOT_FOUND",
            "The passkey challenge is missing or expired",
        ),
        AuthError::PasskeyVerificationFailed => (
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_FAILED",
            "Passkey verification failed",
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            "ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED",
            "The passkey is already registered",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cookie_matches_the_better_auth_cookie_name() {
        let cookie = session_cookie("token.signature", 300, false, true);
        assert_eq!(
            cookie,
            "better-auth.session_token=token.signature; HttpOnly; SameSite=Lax; Path=/; Max-Age=300"
        );
    }
}
