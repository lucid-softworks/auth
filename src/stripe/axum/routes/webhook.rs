use super::support;
use crate::{AxumPluginRoute, StripePlugin, StripeWebhookService};
use axum::{
    Extension, Json,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use serde_json::json;

pub(super) fn route(plugin: StripePlugin) -> AxumPluginRoute {
    AxumPluginRoute::new("/stripe/webhook", post(handle).layer(Extension(plugin)))
}

async fn handle(
    Extension(plugin): Extension<StripePlugin>,
    headers: HeaderMap,
    payload: Bytes,
) -> Response {
    let signature = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok());
    let webhook = StripeWebhookService::new(plugin.options.clone(), plugin.store.clone());
    match webhook.handle_raw(Some(&payload), signature).await {
        Ok(_) => Json(json!({ "success": true })).into_response(),
        Err(error) => support::error(
            error.code(),
            StatusCode::from_u16(error.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        ),
    }
}
