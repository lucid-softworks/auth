use super::{context, status};
use crate::{
    AuthService, PhoneNumberSignInInput,
    axum::{
        body::BetterAuthBody,
        http::{PeerAddress, auth_error, with_bound_session_cookie},
    },
};
use axum::{
    Extension, Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SignInRequest {
    phone_number: String,
    password: String,
    remember_me: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PhoneRequest {
    phone_number: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ResetRequest {
    phone_number: String,
    otp: String,
    new_password: String,
}

pub(super) async fn sign_in(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<SignInRequest>,
) -> Response {
    let remember_me = input.remember_me;
    let request_context = context(&service, &headers, peer);
    match service
        .sign_in_phone_number(PhoneNumberSignInInput {
            phone_number: input.phone_number,
            password: input.password,
            remember_me,
            origin: request_context.origin,
            ip_address: request_context.ip_address,
            user_agent: request_context.user_agent,
        })
        .await
    {
        Ok(result) => {
            let user = match service.better_auth_user(&result.session.user).await {
                Ok(user) => user,
                Err(error) => return auth_error(error),
            };
            let response = Json(json!({ "token": result.token, "user": user }));
            with_bound_session_cookie(
                &service,
                &headers,
                result.session.user.id,
                &result.token,
                remember_me,
                response,
            )
            .await
        }
        Err(error) => auth_error(error),
    }
}

pub(super) async fn request_reset(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<PhoneRequest>,
) -> Response {
    match service
        .request_phone_number_password_reset(&input.phone_number, context(&service, &headers, peer))
        .await
    {
        Ok(()) => Json(status()).into_response(),
        Err(error) => auth_error(error),
    }
}

pub(super) async fn reset_password(
    Extension(service): Extension<Arc<AuthService>>,
    BetterAuthBody(input): BetterAuthBody<ResetRequest>,
) -> Response {
    match service
        .reset_phone_number_password(&input.phone_number, &input.otp, input.new_password)
        .await
    {
        Ok(()) => Json(status()).into_response(),
        Err(error) => auth_error(error),
    }
}
