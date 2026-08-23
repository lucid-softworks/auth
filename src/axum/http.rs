use crate::{
    AuthError, AuthService, SessionWithUser, cookie::ResolvedCookie,
    protocol::better_auth::ErrorResponse,
};
use axum::{
    Extension, Json,
    extract::ConnectInfo,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

pub(super) type PeerAddress = Option<Extension<ConnectInfo<SocketAddr>>>;

pub(super) async fn current_session(
    service: &AuthService,
    headers: &HeaderMap,
) -> Option<SessionWithUser> {
    let token = session_token(service, headers)?;
    service.session(&token).await.ok().flatten()
}

pub(super) fn challenge_token(service: &AuthService, headers: &HeaderMap) -> Option<String> {
    let cookie = service.challenge_cookie();
    signed_cookie_token(service, headers, &cookie.name)
}

pub(super) fn with_challenge_cookie(
    service: &AuthService,
    token: &str,
    body: impl IntoResponse,
) -> Response {
    let cookie = service.challenge_cookie();
    with_cookie(
        body,
        serialize_cookie(&cookie, &service.signed_cookie_value(token), Some(300)),
    )
}

pub(super) fn with_session_cookie(
    service: &AuthService,
    token: &str,
    remember_me: Option<bool>,
    body: impl IntoResponse,
) -> Response {
    let cookie = service.session_cookie();
    let max_age = (remember_me != Some(false)).then(|| service.session_ttl().num_seconds());
    with_cookie(
        body,
        serialize_cookie(&cookie, &service.signed_cookie_value(token), max_age),
    )
}

pub(super) fn clear_session_cookie(service: &AuthService, body: impl IntoResponse) -> Response {
    with_cookie(
        body,
        serialize_cookie(&service.session_cookie(), "", Some(0)),
    )
}

pub fn session_token(service: &AuthService, headers: &HeaderMap) -> Option<String> {
    let cookie = service.session_cookie();
    signed_cookie_token(service, headers, &cookie.name)
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

pub(super) fn client_ip(
    service: &AuthService,
    headers: &HeaderMap,
    peer: PeerAddress,
) -> Option<String> {
    service.resolve_client_ip(
        peer.map(|Extension(ConnectInfo(address))| address.ip()),
        |name| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        },
    )
}

fn serialize_cookie(cookie: &ResolvedCookie, value: &str, max_age_seconds: Option<i64>) -> String {
    let mut serialized = format!("{}={value}", cookie.name);
    if cookie.attributes.http_only {
        serialized.push_str("; HttpOnly");
    }
    serialized.push_str(&format!(
        "; SameSite={}; Path={}",
        cookie.attributes.same_site.as_str(),
        cookie.attributes.path
    ));
    if let Some(domain) = &cookie.attributes.domain {
        serialized.push_str(&format!("; Domain={domain}"));
    }
    if let Some(max_age) = max_age_seconds {
        serialized.push_str(&format!("; Max-Age={max_age}"));
    }
    if cookie.attributes.secure {
        serialized.push_str("; Secure");
    }
    serialized
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
        | AuthError::StepUpRequired
        | AuthError::NotFound
        | AuthError::UserAlreadyExists
        | AuthError::LastOwner
        | AuthError::SoleOwnerRecoveryUnavailable
        | AuthError::InvalidGuestGrant
        | AuthError::InvalidRequest(_) => access_error_details(&error),
        AuthError::CredentialAccountNotFound
        | AuthError::InvalidPassword
        | AuthError::PasswordTooShort
        | AuthError::PasswordTooLong
        | AuthError::PasswordCompromised => password_error_details(&error),
        AuthError::PasskeyNotFound
        | AuthError::LastPasskey
        | AuthError::PasskeyDisabled
        | AuthError::PasskeyChallengeExpired
        | AuthError::PasskeyVerificationFailed
        | AuthError::CredentialAlreadyRegistered => passkey_error_details(&error),
        AuthError::RecoveryCodesNotEnabled | AuthError::InvalidRecoveryCode => {
            recovery_error_details(&error)
        }
        AuthError::InvalidSession => (
            StatusCode::UNAUTHORIZED,
            "INVALID_SESSION",
            "The session is invalid or expired",
        ),
        AuthError::InvalidApiKey => (
            StatusCode::UNAUTHORIZED,
            "INVALID_API_KEY",
            "The API key is invalid, expired, or revoked",
        ),
        AuthError::InvalidOrigin
        | AuthError::MissingOrigin
        | AuthError::InvalidCallbackUrl
        | AuthError::InvalidRedirectUrl
        | AuthError::InvalidErrorCallbackUrl
        | AuthError::InvalidNewUserCallbackUrl
        | AuthError::CrossSiteNavigationLogin => request_security_error_details(&error),
        AuthError::InvalidConfiguration(_)
        | AuthError::Storage(_)
        | AuthError::Worker
        | AuthError::PasswordCheckUnavailable => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "Authentication failed",
        ),
    };
    (status, Json(ErrorResponse { code, message })).into_response()
}

type ErrorDetails = (StatusCode, &'static str, &'static str);

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
        AuthError::LastOwner => (
            StatusCode::CONFLICT,
            "LAST_OWNER",
            "The final owner account cannot be removed or disabled",
        ),
        AuthError::SoleOwnerRecoveryUnavailable => (
            StatusCode::FORBIDDEN,
            "SOLE_OWNER_RECOVERY_UNAVAILABLE",
            "Local recovery requires the named account to be the sole owner",
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
        AuthError::PasswordCompromised => (
            StatusCode::BAD_REQUEST,
            "PASSWORD_COMPROMISED",
            "The password has been compromised. Choose a different password",
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
        AuthError::LastPasskey => (
            StatusCode::CONFLICT,
            "LAST_PASSKEY",
            "An MFA-required account must keep at least one passkey",
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

fn recovery_error_details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::RecoveryCodesNotEnabled => (
            StatusCode::BAD_REQUEST,
            "BACKUP_CODES_NOT_ENABLED",
            "Recovery codes are not enabled for this account",
        ),
        _ => (
            StatusCode::UNAUTHORIZED,
            "INVALID_BACKUP_CODE",
            "The recovery code is invalid",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cookie_matches_the_better_auth_cookie_name() {
        let cookie = crate::CookieConfig::default().resolve(
            crate::cookie::CookieKind::SessionToken,
            false,
            None,
        );
        let cookie = serialize_cookie(&cookie, "token.signature", Some(300));
        assert_eq!(
            cookie,
            "better-auth.session_token=token.signature; HttpOnly; SameSite=Lax; Path=/; Max-Age=300"
        );
    }

    #[test]
    fn cookie_expiration_preserves_creation_scope() {
        let mut config = crate::CookieConfig::default();
        config.default_attributes.path = Some("/auth".into());
        config.default_attributes.domain = Some(".example.com".into());
        let cookie = config.resolve(crate::cookie::CookieKind::SessionToken, true, None);
        assert_eq!(
            serialize_cookie(&cookie, "", Some(0)),
            "__Secure-better-auth.session_token=; HttpOnly; SameSite=Lax; Path=/auth; Domain=.example.com; Max-Age=0; Secure"
        );
    }
}
