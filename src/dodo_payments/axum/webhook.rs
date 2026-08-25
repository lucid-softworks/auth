use super::support;
use crate::{
    AxumPluginRoute,
    dodo_payments::{
        DodoWebhookCallbacks,
        webhook::{DodoWebhookError, process_dodo_webhook},
    },
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
pub(crate) struct DodoWebhookRouteState {
    secret: Arc<str>,
    callbacks: DodoWebhookCallbacks,
}

impl DodoWebhookRouteState {
    pub(crate) fn new(secret: impl Into<Arc<str>>, callbacks: DodoWebhookCallbacks) -> Self {
        Self {
            secret: secret.into(),
            callbacks,
        }
    }
}

pub(crate) fn webhook_route(state: DodoWebhookRouteState) -> AxumPluginRoute {
    AxumPluginRoute::new(
        "/dodopayments/webhooks",
        post(handle).layer(Extension(state)),
    )
}

async fn handle(
    Extension(state): Extension<DodoWebhookRouteState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.is_empty() {
        return support::internal_empty();
    }
    if state.secret.is_empty() {
        return webhook_error("DodoPayments webhook webhookKey not found");
    }
    let body = String::from_utf8_lossy(&body);
    let result = process_dodo_webhook(
        &body,
        header(&headers, "webhook-id"),
        header(&headers, "webhook-timestamp"),
        header(&headers, "webhook-signature"),
        &state.secret,
        &state.callbacks,
    )
    .await;
    match result {
        Ok(_) => Json(json!({ "received": true })).into_response(),
        Err(DodoWebhookError::Callback(error)) => {
            tracing::error!(message = %error, "DodoPayments webhook callback failed");
            support::error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Webhook error: See server logs for more information.",
            )
        }
        Err(error) => webhook_error(&error.to_string()),
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn webhook_error(message: &str) -> Response {
    tracing::error!(message, "DodoPayments webhook verification failed");
    support::error(
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        format!("Webhook Error: {message}"),
    )
}
