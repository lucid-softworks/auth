use crate::{
    AuthError, AuthService,
    protocol::better_auth::{
        AnonymousSignInResponse, BetterAuthPasskey, BetterAuthUser, DeletePasskeyRequest,
        SessionResponse, SignInResponse, StatusResponse, SuccessResponse, UpdatePasskeyRequest,
        UpdatePasskeyResponse, UsernameAvailabilityRequest, UsernameAvailabilityResponse,
        UsernameSignInRequest,
    },
};
use axum::{
    Extension, Json, Router,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::Arc;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

mod account;
mod admin;
mod guest;
mod http;

pub use self::http::session_token;
use self::http::{
    auth_error, challenge_token, clear_session_cookie, current_session, user_agent,
    with_challenge_cookie, with_session_cookie,
};

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
        .route("/api/auth/passkey/delete-passkey", post(delete_passkey))
        .route("/api/auth/passkey/update-passkey", post(update_passkey))
        .merge(account::router())
        .merge(admin::router())
        .merge(guest::router())
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
    clear_session_cookie(&service, Json(SuccessResponse { success: true }))
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

async fn delete_passkey(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<DeletePasskeyRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let Ok(passkey_id) = input.id.parse() else {
        return auth_error(AuthError::PasskeyNotFound);
    };
    match service.delete_passkey(&session, passkey_id).await {
        Ok(()) => Json(StatusResponse { status: true }).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn update_passkey(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<UpdatePasskeyRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    let Ok(passkey_id) = input.id.parse() else {
        return auth_error(AuthError::PasskeyNotFound);
    };
    match service
        .rename_passkey(&session, passkey_id, &input.name)
        .await
    {
        Ok(passkey) => Json(UpdatePasskeyResponse {
            passkey: BetterAuthPasskey::from(&passkey),
        })
        .into_response(),
        Err(error) => auth_error(error),
    }
}
