use super::{
    body::BetterAuthBody,
    http::{PeerAddress, auth_error, client_ip, current_session, user_agent, with_session_cookie},
};
use crate::{
    AuthError, AuthService, EmailSignUpInput,
    protocol::better_auth::{
        EmailSignInRequest, EmailSignUpRequest, EmailSignUpResponse, PasswordResetCallbackQuery,
        PasswordResetRequestResponse, RequestPasswordResetRequest, ResetPasswordQuery,
        ResetPasswordRequest, SendVerificationEmailRequest, StatusResponse, VerifyEmailQuery,
        VerifyEmailResponse, VerifyPasswordRequest,
    },
};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use std::sync::Arc;

pub(super) fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/sign-up/email", post(sign_up_email))
        .route("/sign-in/email", post(sign_in_email))
        .route("/verify-password", post(verify_password))
        .route("/request-password-reset", post(request_password_reset))
        .route(
            "/reset-password/{token}",
            axum::routing::get(reset_password_callback),
        )
        .route("/reset-password", post(reset_password))
        .route("/send-verification-email", post(send_verification_email))
        .route("/verify-email", axum::routing::get(verify_email))
}

const RESET_REQUEST_MESSAGE: &str =
    "If this email exists in our system, check your email for the reset link";

async fn request_password_reset(
    Extension(service): Extension<Arc<AuthService>>,
    Json(input): Json<RequestPasswordResetRequest>,
) -> Response {
    match service
        .request_password_reset(&input.email, input.redirect_to.as_deref())
        .await
    {
        Ok(()) => Json(PasswordResetRequestResponse {
            status: true,
            message: RESET_REQUEST_MESSAGE,
        })
        .into_response(),
        Err(error) => auth_error(error),
    }
}

async fn reset_password_callback(
    Extension(service): Extension<Arc<AuthService>>,
    Path(token): Path<String>,
    Query(query): Query<PasswordResetCallbackQuery>,
) -> Response {
    let valid = if token.is_empty() || query.callback_url.is_empty() {
        false
    } else {
        match service.password_reset_token_valid(&token).await {
            Ok(valid) => valid,
            Err(error) => return auth_error(error),
        }
    };
    let (key, value) = if valid {
        ("token", token.as_str())
    } else {
        ("error", "INVALID_TOKEN")
    };
    match service.password_reset_redirect(Some(&query.callback_url), key, value) {
        Ok(location) => redirect(&location),
        Err(error) => auth_error(error),
    }
}

async fn reset_password(
    Extension(service): Extension<Arc<AuthService>>,
    Query(query): Query<ResetPasswordQuery>,
    Json(input): Json<ResetPasswordRequest>,
) -> Response {
    let Some(token) = input
        .token
        .filter(|token| !token.is_empty())
        .or(query.token)
    else {
        return auth_error(AuthError::InvalidPasswordResetToken);
    };
    match service.reset_password(&token, input.new_password).await {
        Ok(()) => Json(StatusResponse { status: true }).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn send_verification_email(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<SendVerificationEmailRequest>,
) -> Response {
    let session = current_session(&service, &headers).await;
    match service
        .send_verification_email(
            &input.email,
            input.callback_url.as_deref(),
            session.as_ref(),
        )
        .await
    {
        Ok(()) => Json(StatusResponse { status: true }).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn verify_email(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<VerifyEmailQuery>,
) -> Response {
    let token = super::http::session_token(&service, &headers);
    let session = current_session(&service, &headers).await;
    let current = session.as_ref().zip(token.as_deref());
    match service
        .verify_email_token_with_callback(&query.token, current, query.callback_url.as_deref())
        .await
    {
        Ok(result) => {
            if let (Some(source), Some(token)) = (session.as_ref(), result.session_token.as_ref())
                && source.user.is_anonymous
            {
                let upgraded = match service.session(token).await {
                    Ok(Some(session)) => crate::SignInResult {
                        token: token.clone(),
                        session,
                    },
                    Ok(None) => return auth_error(AuthError::InvalidSession),
                    Err(error) => return auth_error(error),
                };
                if let Err(error) = service.complete_anonymous_upgrade(source, &upgraded).await {
                    return auth_error(error);
                }
            }
            let response = match query.callback_url {
                Some(callback_url) => redirect(&callback_url),
                None => {
                    let user = if result.user_in_response {
                        match service.better_auth_user(&result.user).await {
                            Ok(user) => Some(user),
                            Err(error) => return auth_error(error),
                        }
                    } else {
                        None
                    };
                    Json(VerifyEmailResponse { status: true, user }).into_response()
                }
            };
            match result.session_token {
                Some(token) => with_session_cookie(&service, &token, Some(true), response),
                None => response,
            }
        }
        Err(error) => {
            if let Some(callback_url) = query.callback_url
                && let Some(code) = verification_error_code(&error)
            {
                return redirect_error(&callback_url, code);
            }
            auth_error(error)
        }
    }
}

fn redirect(callback_url: &str) -> Response {
    match HeaderValue::from_str(callback_url) {
        Ok(location) => (StatusCode::FOUND, [(header::LOCATION, location)]).into_response(),
        Err(_) => auth_error(AuthError::InvalidCallbackUrl),
    }
}

fn redirect_error(callback_url: &str, code: &str) -> Response {
    let separator = if callback_url.contains('?') { '&' } else { '?' };
    redirect(&format!("{callback_url}{separator}error={code}"))
}

fn verification_error_code(error: &AuthError) -> Option<&'static str> {
    match error {
        AuthError::TokenExpired => Some("TOKEN_EXPIRED"),
        AuthError::VerificationUserNotFound => Some("USER_NOT_FOUND"),
        AuthError::InvalidToken => Some("INVALID_TOKEN"),
        AuthError::InvalidUser => Some("INVALID_USER"),
        _ => None,
    }
}

async fn verify_password(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Json(input): Json<VerifyPasswordRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::InvalidSession);
    };
    match service
        .verify_current_password(&session, input.password)
        .await
    {
        Ok(()) => Json(StatusResponse { status: true }).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn sign_up_email(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<EmailSignUpRequest>,
) -> Response {
    let anonymous = current_session(&service, &headers)
        .await
        .filter(|session| session.user.is_anonymous);
    let remember_me = input.remember_me;
    match service
        .sign_up_email(
            EmailSignUpInput {
                name: input.name,
                email: input.email,
                password: input.password,
                image: input.image,
                callback_url: input.callback_url,
                remember_me: input.remember_me,
                username: input.username,
                display_username: input.display_username,
            },
            client_ip(&service, &headers, peer),
            user_agent(&headers),
        )
        .await
    {
        Ok(result) => {
            if let (Some(source), Some(token)) = (anonymous.as_ref(), result.token.as_ref()) {
                let upgraded = match service.session(token).await {
                    Ok(Some(session)) => crate::SignInResult {
                        token: token.clone(),
                        session,
                    },
                    Ok(None) => return auth_error(AuthError::InvalidSession),
                    Err(error) => return auth_error(error),
                };
                if let Err(error) = service.complete_anonymous_upgrade(source, &upgraded).await {
                    return auth_error(error);
                }
            }
            let token = result.token.clone();
            let user = match service.better_auth_user(&result.user).await {
                Ok(user) => user,
                Err(error) => return auth_error(error),
            };
            let response = Json(EmailSignUpResponse {
                token: result.token,
                user,
            });
            match token {
                Some(token) => with_session_cookie(&service, &token, remember_me, response),
                None => response.into_response(),
            }
        }
        Err(error) => auth_error(error),
    }
}

async fn sign_in_email(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<EmailSignInRequest>,
) -> Response {
    let anonymous = current_session(&service, &headers)
        .await
        .filter(|session| session.user.is_anonymous);
    let callback_url = input.callback_url.clone();
    match service
        .sign_in_email(
            &input.email,
            input.password,
            input.remember_me,
            input.callback_url.as_deref(),
            client_ip(&service, &headers, peer),
            user_agent(&headers),
        )
        .await
    {
        Ok(result) => {
            crate::two_factor::axum::finish_password_sign_in(
                &service,
                &headers,
                result,
                input.remember_me,
                callback_url,
                anonymous,
            )
            .await
        }
        Err(error) => auth_error(error),
    }
}
