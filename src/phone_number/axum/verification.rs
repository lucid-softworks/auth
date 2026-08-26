use super::context;
use crate::{
    AuthService, PhoneNumberVerifyInput,
    axum::{
        body::BetterAuthBody,
        http::{PeerAddress, auth_error, current_session, with_bound_session_cookie},
    },
};
use axum::{
    Extension, Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SendRequest {
    phone_number: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct VerifyRequest {
    phone_number: String,
    code: String,
    #[serde(default)]
    disable_session: bool,
    #[serde(default)]
    update_phone_number: bool,
    #[serde(flatten)]
    additional_fields: Map<String, Value>,
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
    match service
        .send_phone_number_otp(&input.phone_number, context(&service, &headers, peer))
        .await
    {
        Ok(()) => Json(serde_json::json!({ "message": "code sent" })).into_response(),
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
    let update_phone_number = input.update_phone_number;
    let request_context = context(&service, &headers, peer);
    match service
        .verify_phone_number(
            current.as_ref(),
            PhoneNumberVerifyInput {
                phone_number: input.phone_number,
                code: input.code,
                disable_session: input.disable_session,
                update_phone_number,
                additional_fields: input.additional_fields,
                origin: request_context.origin,
                ip_address: request_context.ip_address,
                user_agent: request_context.user_agent,
            },
        )
        .await
    {
        Ok(result) => {
            let user_id = result.user.id.clone();
            let user = match service.better_auth_user(&result.user).await {
                Ok(user) => user,
                Err(error) => return auth_error(error),
            };
            let response = Json(VerifyResponse {
                status: true,
                token: result.token.clone(),
                user,
            });
            match result.token {
                Some(token) => {
                    with_bound_session_cookie(
                        &service,
                        &headers,
                        &user_id,
                        &token,
                        Some(true),
                        response,
                    )
                    .await
                }
                None => response.into_response(),
            }
        }
        Err(error) => auth_error(error),
    }
}
