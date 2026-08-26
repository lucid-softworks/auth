use super::{SuccessResponse, context, parse_type, success};
use crate::{
    AuthService,
    axum::{
        body::BetterAuthBody,
        http::{
            PeerAddress, auth_error, client_ip, current_session, dont_remember, user_agent,
            with_bound_session_cookie, with_session_cache_cookie,
        },
    },
};
use axum::{
    Extension, Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
pub(super) struct SendRequest {
    email: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
pub(super) struct CheckRequest {
    email: String,
    #[serde(rename = "type")]
    kind: String,
    otp: String,
}

#[derive(Deserialize)]
pub(super) struct VerifyRequest {
    email: String,
    otp: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyResponse {
    status: bool,
    token: Option<String>,
    user: crate::protocol::better_auth::BetterAuthUser,
}

pub(super) async fn send(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<SendRequest>,
) -> Response {
    let kind = match parse_type(&input.kind) {
        Ok(kind) => kind,
        Err(error) => return auth_error(error),
    };
    match service
        .send_email_otp(&input.email, kind, context(&service, &headers, peer))
        .await
    {
        Ok(()) => Json(success()).into_response(),
        Err(error) => auth_error(error),
    }
}

pub(super) async fn check(
    Extension(service): Extension<Arc<AuthService>>,
    BetterAuthBody(input): BetterAuthBody<CheckRequest>,
) -> Response {
    let kind = match parse_type(&input.kind) {
        Ok(kind) => kind,
        Err(error) => return auth_error(error),
    };
    match service
        .check_email_otp(&input.email, kind, &input.otp)
        .await
    {
        Ok(()) => Json(SuccessResponse { success: true }).into_response(),
        Err(error) => auth_error(error),
    }
}

pub(super) async fn verify(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<VerifyRequest>,
) -> Response {
    let current = current_session(&service, &headers).await;
    match service
        .verify_email_otp(
            &input.email,
            &input.otp,
            client_ip(&service, &headers, peer),
            user_agent(&headers),
        )
        .await
    {
        Ok(result) => verified_response(&service, &headers, current, result).await,
        Err(error) => auth_error(error),
    }
}

async fn verified_response(
    service: &AuthService,
    headers: &HeaderMap,
    current: Option<crate::SessionWithUser>,
    result: crate::EmailOtpVerification,
) -> Response {
    let token = result.session.as_ref().map(|session| session.token.clone());
    let user_id = result.user.id.clone();
    let user = match service.better_auth_user(&result.user).await {
        Ok(user) => user,
        Err(error) => return auth_error(error),
    };
    let response = Json(VerifyResponse {
        status: true,
        token: token.clone(),
        user,
    });
    match token {
        Some(token) => {
            with_bound_session_cookie(service, headers, &user_id, &token, Some(true), response)
                .await
        }
        None => match current.filter(|session| session.user.id == user_id) {
            Some(mut current) => {
                current.user = result.user;
                with_session_cache_cookie(
                    service,
                    headers,
                    &current.session.token,
                    Some(&current),
                    Some(!dont_remember(service, headers)),
                    response,
                )
                .await
            }
            None => response.into_response(),
        },
    }
}
