use super::support;
use crate::{
    AxumPluginRoute,
    polar::webhook::{PolarWebhookCallbacks, PolarWebhookHeaders, verify_webhook},
};
use axum::{
    Extension, Json,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct WebhookRouteState {
    secret: Option<Arc<str>>,
    callbacks: PolarWebhookCallbacks,
}

impl WebhookRouteState {
    pub(crate) fn new(secret: Option<Arc<str>>, callbacks: PolarWebhookCallbacks) -> Self {
        Self { secret, callbacks }
    }
}

pub(crate) fn route(state: WebhookRouteState) -> AxumPluginRoute {
    AxumPluginRoute::new("/polar/webhooks", post(handle).layer(Extension(state)))
}

async fn handle(
    Extension(state): Extension<WebhookRouteState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.is_empty()
        && !headers.contains_key(axum::http::header::CONTENT_LENGTH)
        && !headers.contains_key(axum::http::header::TRANSFER_ENCODING)
    {
        return support::internal("Internal server error");
    }
    let Some(secret) = state.secret.as_deref().filter(|secret| !secret.is_empty()) else {
        return webhook_error("Polar webhook secret not found");
    };
    let headers = PolarWebhookHeaders {
        webhook_id: header(&headers, "webhook-id"),
        webhook_timestamp: header(&headers, "webhook-timestamp"),
        webhook_signature: header(&headers, "webhook-signature"),
    };
    let body = String::from_utf8_lossy(&body);
    let event = match verify_webhook(&body, &headers, secret) {
        Ok(event) => event,
        Err(error) => return webhook_error(&error.to_string()),
    };
    if let Err(error) = state.callbacks.dispatch(&event).await {
        tracing::error!(message = %error, event = event.event_type.as_str(), "Polar webhook callback failed");
        return support::error_response(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Webhook error: See server logs for more information.",
        );
    }
    Json(json!({ "received": true })).into_response()
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn webhook_error(message: &str) -> Response {
    support::error_response(
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        format!("Webhook Error: {message}"),
    )
}
