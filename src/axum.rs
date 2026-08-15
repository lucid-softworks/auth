use crate::{
    AuthError, AuthService,
    protocol::better_auth::{
        AnonymousSignInResponse, BetterAuthPasskey, BetterAuthUser, ErrorResponse,
        PASSKEY_CHALLENGE_COOKIE_NAME, SESSION_COOKIE_NAME, SessionResponse, SignInResponse,
        SuccessResponse, UsernameAvailabilityRequest, UsernameAvailabilityResponse,
        UsernameSignInRequest,
    },
};
use axum::{
    Extension, Json, Router,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::Arc;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

pub fn router<S>(service: Arc<AuthService>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/api/auth/get-session", get(get_session))
        .route("/api/auth/sign-in/username", post(sign_in_username))
        .route("/api/auth/sign-out", post(sign_out))
        .route("/api/auth/sign-in/anonymous", post(sign_in_anonymous))
        .route(
            "/api/auth/is-username-available",
            post(is_username_available),
        )
        .route(
            "/api/auth/passkey/generate-register-options",
            get(generate_passkey_registration_options),
        )
        .route(
            "/api/auth/passkey/verify-registration",
            post(verify_passkey_registration),
        )
        .route(
            "/api/auth/passkey/generate-authenticate-options",
            get(generate_passkey_authentication_options),
        )
        .route(
            "/api/auth/passkey/verify-authentication",
            post(verify_passkey_authentication),
        )
        .route(
            "/api/auth/passkey/list-user-passkeys",
            get(list_user_passkeys),
        )
        .layer(Extension(service))
}

#[derive(Debug, Deserialize)]
struct VerifyRegistrationRequest {
    response: RegisterPublicKeyCredential,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyAuthenticationRequest {
    response: PublicKeyCredential,
}

async fn sign_in_username(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<UsernameSignInRequest>,
) -> Response {
    let callback_url = input.callback_url.clone();
    match service
        .sign_in_username(&input.username, input.password, None, user_agent(&headers))
        .await
    {
        Ok(result) => {
            let response = SignInResponse {
                redirect: callback_url.is_some(),
                token: result.token.clone(),
                url: callback_url,
                user: BetterAuthUser::from(&result.session.user),
                two_factor_redirect: result.session.session.assurance
                    == crate::Assurance::PasswordPendingPasskey,
            };
            with_session_cookie(&service, &result.token, input.remember_me, Json(response))
        }
        Err(error) => auth_error(error),
    }
}

async fn sign_in_anonymous(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    match service.sign_in_anonymous(None, user_agent(&headers)).await {
        Ok(result) => {
            let response = AnonymousSignInResponse {
                token: result.token.clone(),
                user: BetterAuthUser::from(&result.session.user),
            };
            with_session_cookie(&service, &result.token, Some(true), Json(response))
        }
        Err(error) => auth_error(error),
    }
}

async fn get_session(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    let mut response = match session_token(&service, &headers) {
        Some(token) => match service.session(&token).await {
            Ok(Some(session)) => Json(Some(SessionResponse::new(&session, token))).into_response(),
            Ok(None) => Json::<Option<SessionResponse>>(None).into_response(),
            Err(error) => return auth_error(error),
        },
        None => Json(
            service
                .development_session()
                .as_ref()
                .map(|session| SessionResponse::new(session, "development-bypass")),
        )
        .into_response(),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

async fn sign_out(Extension(service): Extension<Arc<AuthService>>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token(&service, &headers)
        && let Err(error) = service.sign_out(&token).await
    {
        return auth_error(error);
    }
    let mut response = Json(SuccessResponse { success: true }).into_response();
    let cookie = expired_cookie(service.cookie_secure());
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

async fn is_username_available(
    Extension(service): Extension<Arc<AuthService>>,
    Json(input): Json<UsernameAvailabilityRequest>,
) -> Response {
    let result = service.username_available(&input.username).await;
    match result {
        Ok(available) => Json(UsernameAvailabilityResponse { available }).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn generate_passkey_registration_options(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service.start_passkey_registration(&session.user).await {
        Ok((token, options)) => with_challenge_cookie(&service, &token, Json(options.public_key)),
        Err(error) => auth_error(error),
    }
}

async fn verify_passkey_registration(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<VerifyRegistrationRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let Some(challenge) = challenge_token(&service, &headers) else {
        return auth_error(AuthError::PasskeyChallengeExpired);
    };
    match service
        .finish_passkey_registration(&challenge, session.user.id, input.response, input.name)
        .await
    {
        Ok(passkey) => Json(BetterAuthPasskey::from(&passkey)).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn generate_passkey_authentication_options(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    let session = current_session(&service, &headers).await;
    match service.start_passkey_authentication(session.as_ref()).await {
        Ok((token, options)) => with_challenge_cookie(&service, &token, Json(options.public_key)),
        Err(error) => auth_error(error),
    }
}

async fn verify_passkey_authentication(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<VerifyAuthenticationRequest>,
) -> Response {
    let Some(challenge) = challenge_token(&service, &headers) else {
        return auth_error(AuthError::PasskeyChallengeExpired);
    };
    match service
        .finish_passkey_authentication(&challenge, input.response, None, user_agent(&headers))
        .await
    {
        Ok(result) => {
            let response = SessionResponse::new(&result.session, result.token.clone());
            with_session_cookie(&service, &result.token, Some(true), Json(response))
        }
        Err(error) => auth_error(error),
    }
}

async fn list_user_passkeys(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service.list_passkeys(session.user.id).await {
        Ok(passkeys) => Json(
            passkeys
                .iter()
                .map(BetterAuthPasskey::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => auth_error(error),
    }
}

async fn current_session(
    service: &AuthService,
    headers: &HeaderMap,
) -> Option<crate::SessionWithUser> {
    let token = session_token(service, headers)?;
    service.session(&token).await.ok().flatten()
}

fn challenge_token(service: &AuthService, headers: &HeaderMap) -> Option<String> {
    signed_cookie_token(service, headers, PASSKEY_CHALLENGE_COOKIE_NAME)
}

fn with_challenge_cookie(service: &AuthService, token: &str, body: impl IntoResponse) -> Response {
    let mut response = body.into_response();
    let cookie = named_cookie(
        PASSKEY_CHALLENGE_COOKIE_NAME,
        &service.signed_cookie_value(token),
        300,
        service.cookie_secure(),
        true,
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

fn with_session_cookie(
    service: &AuthService,
    token: &str,
    remember_me: Option<bool>,
    body: impl IntoResponse,
) -> Response {
    let mut response = body.into_response();
    let cookie = session_cookie(
        &service.signed_cookie_value(token),
        service.session_ttl().num_seconds(),
        service.cookie_secure(),
        remember_me != Some(false),
    );
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

fn user_agent(headers: &HeaderMap) -> Option<String> {
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

fn expired_cookie(secure: bool) -> String {
    session_cookie("", 0, secure, true)
}

fn auth_error(error: AuthError) -> Response {
    let (status, code, message) = match error {
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
        AuthError::CredentialAlreadyRegistered => (
            StatusCode::BAD_REQUEST,
            "ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED",
            "The passkey is already registered",
        ),
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
