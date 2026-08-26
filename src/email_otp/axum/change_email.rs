use super::{context, success};
use crate::{
    AuthError, AuthService,
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
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Request {
    new_email: String,
    otp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ChangeRequest {
    new_email: String,
    otp: String,
}

pub(super) async fn request(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<Request>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    match service
        .request_email_change_email_otp(
            &session,
            &input.new_email,
            input.otp.as_deref(),
            context(&service, &headers, peer),
        )
        .await
    {
        Ok(()) => Json(success()).into_response(),
        Err(error) => auth_error(error),
    }
}

pub(super) async fn change(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<ChangeRequest>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    match service
        .change_email_email_otp(&session, &input.new_email, &input.otp)
        .await
    {
        Ok(user) => {
            with_bound_session_cookie(
                &service,
                &headers,
                &user.id,
                &session.session.token,
                Some(true),
                Json(success()),
            )
            .await
        }
        Err(error) => auth_error(error),
    }
}
