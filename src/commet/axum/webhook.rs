use super::support;
use crate::{
    AxumPluginRoute,
    commet::{CommetWebhookCallbacks, webhook::CommetWebhookError},
};
use axum::{
    Extension,
    body::Bytes,
    http::{HeaderMap, StatusCode, header},
    routing::post,
};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
struct State {
    secret: Arc<str>,
    callbacks: CommetWebhookCallbacks,
}

pub(super) fn route(secret: Arc<str>, callbacks: CommetWebhookCallbacks) -> AxumPluginRoute {
    AxumPluginRoute::new(
        "/commet/webhooks",
        post(handle).layer(Extension(State { secret, callbacks })),
    )
}

async fn handle(
    Extension(state): Extension<State>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if body.is_empty() && content_type.is_none() {
        return support::message(StatusCode::BAD_REQUEST, "Request body is required");
    }
    if !content_type.is_some_and(|value| value.eq_ignore_ascii_case("application/json")) {
        let actual = content_type.unwrap_or("");
        return support::coded(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            format!("Content-Type \"{actual}\" is not allowed. Allowed types: application/json"),
        );
    }
    let body = String::from_utf8_lossy(&body);
    if serde_json::from_str::<serde_json::Value>(&body).is_err() {
        return support::coded(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid JSON in request body",
        );
    }
    let signature = headers
        .get("x-commet-signature")
        .and_then(|value| value.to_str().ok());
    match crate::commet::webhook::process_commet_webhook(
        &body,
        signature,
        &state.secret,
        &state.callbacks,
    )
    .await
    {
        Ok(_) => support::json(json!({"received": true})),
        Err(CommetWebhookError::InvalidSignature) => {
            support::message(StatusCode::UNAUTHORIZED, "Invalid webhook signature")
        }
        Err(CommetWebhookError::Handler(error)) => {
            tracing::error!(message = %error, "Commet webhook handler failed");
            support::message(StatusCode::INTERNAL_SERVER_ERROR, "Webhook handler error")
        }
    }
}
