use super::{context, success};
use crate::{
    AuthService, EmailOtpSignInInput,
    axum::{
        body::BetterAuthBody,
        http::{PeerAddress, auth_error, client_ip, user_agent, with_bound_session_cookie},
    },
};
use axum::{
    Extension, Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::Arc;

#[derive(Deserialize)]
pub(super) struct SignInRequest {
    email: String,
    otp: String,
    name: Option<String>,
    image: Option<String>,
    #[serde(flatten)]
    additional_fields: Map<String, Value>,
}

#[derive(Deserialize)]
pub(super) struct EmailRequest {
    email: String,
}

#[derive(Deserialize)]
pub(super) struct ResetRequest {
    email: String,
    otp: String,
    password: String,
}

pub(super) async fn sign_in(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<SignInRequest>,
) -> Response {
    match service
        .sign_in_email_otp(EmailOtpSignInInput {
            email: input.email,
            otp: input.otp,
            name: input.name,
            image: input.image,
            additional_fields: input.additional_fields,
            ip_address: client_ip(&service, &headers, peer),
            user_agent: user_agent(&headers),
        })
        .await
    {
        Ok(result) => sign_in_response(&service, &headers, result).await,
        Err(error) => auth_error(error),
    }
}

async fn sign_in_response(
    service: &AuthService,
    headers: &HeaderMap,
    result: crate::SignInResult,
) -> Response {
    let user = match service.better_auth_user(&result.session.user).await {
        Ok(user) => user,
        Err(error) => return auth_error(error),
    };
    let response = Json(json!({ "token": result.token, "user": user }));
    with_bound_session_cookie(
        service,
        headers,
        result.session.user.id,
        &result.token,
        Some(true),
        response,
    )
    .await
}

pub(super) async fn request_reset(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<EmailRequest>,
) -> Response {
    match service
        .request_password_reset_email_otp(&input.email, context(&service, &headers, peer))
        .await
    {
        Ok(()) => Json(success()).into_response(),
        Err(error) => auth_error(error),
    }
}

pub(super) async fn reset(
    Extension(service): Extension<Arc<AuthService>>,
    BetterAuthBody(input): BetterAuthBody<ResetRequest>,
) -> Response {
    match service
        .reset_password_email_otp(&input.email, &input.otp, input.password)
        .await
    {
        Ok(()) => Json(success()).into_response(),
        Err(error) => auth_error(error),
    }
}
