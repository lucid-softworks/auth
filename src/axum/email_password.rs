use super::{
    body::BetterAuthBody,
    http::{PeerAddress, auth_error, client_ip, current_session, user_agent, with_session_cookie},
    sign_in_response,
};
use crate::{
    AuthError, AuthService, EmailSignUpInput,
    protocol::better_auth::{
        BetterAuthUser, EmailSignInRequest, EmailSignUpRequest, EmailSignUpResponse,
        StatusResponse, VerifyPasswordRequest,
    },
};
use axum::{
    Extension, Json, Router,
    http::{HeaderMap, HeaderValue, header},
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
    match service
        .sign_up_email(
            EmailSignUpInput {
                name: input.name,
                email: input.email,
                password: input.password,
                image: input.image,
                remember_me: input.remember_me,
            },
            client_ip(&service, &headers, peer),
            user_agent(&headers),
        )
        .await
    {
        Ok(result) => {
            let token = result.token.clone();
            let response = Json(EmailSignUpResponse {
                token: result.token,
                user: BetterAuthUser::from(&result.user),
            });
            match token {
                Some(token) => with_session_cookie(&service, &token, input.remember_me, response),
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
    let callback_url = input.callback_url.clone();
    match service
        .sign_in_email(
            &input.email,
            input.password,
            input.remember_me,
            client_ip(&service, &headers, peer),
            user_agent(&headers),
        )
        .await
    {
        Ok(result) => {
            let token = result.token.clone();
            let mut response = with_session_cookie(
                &service,
                &token,
                input.remember_me,
                Json(sign_in_response(result, callback_url.clone())),
            );
            if let Some(callback_url) = callback_url
                && let Ok(location) = HeaderValue::from_str(&callback_url)
            {
                response.headers_mut().insert(header::LOCATION, location);
            }
            response
        }
        Err(error) => auth_error(error),
    }
}
