use crate::{
    AuthService, AxumPluginRoute,
    axum::body::BetterAuthBody,
    protocol::better_auth::{
        UsernameAvailabilityRequest, UsernameAvailabilityResponse, UsernameSignInRequest,
    },
};
use axum::{
    Extension, Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::post,
};
use std::sync::Arc;

pub(super) fn routes(service: Arc<AuthService>) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/sign-in/username",
            post(sign_in).layer(Extension(service.clone())),
        ),
        AxumPluginRoute::new(
            "/is-username-available",
            post(available).layer(Extension(service)),
        ),
    ]
}

async fn sign_in(
    Extension(service): Extension<Arc<AuthService>>,
    peer: crate::axum::http::PeerAddress,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<UsernameSignInRequest>,
) -> Response {
    let anonymous = crate::axum::http::current_session(&service, &headers)
        .await
        .filter(|session| session.user.is_anonymous);
    let callback_url = input.callback_url.clone();
    match service
        .sign_in_username_plugin(
            &input.username,
            input.password,
            input.remember_me,
            input.callback_url.as_deref(),
            crate::axum::http::client_ip(&service, &headers, peer),
            crate::axum::http::user_agent(&headers),
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
        Err(error) => super::error::http_error(error, axum::http::StatusCode::UNPROCESSABLE_ENTITY),
    }
}

async fn available(
    Extension(service): Extension<Arc<AuthService>>,
    Json(input): Json<UsernameAvailabilityRequest>,
) -> Response {
    match service.username_available_plugin(&input.username).await {
        Ok(available) => Json(UsernameAvailabilityResponse { available }).into_response(),
        Err(error) => super::error::http_error(error, axum::http::StatusCode::UNPROCESSABLE_ENTITY),
    }
}
