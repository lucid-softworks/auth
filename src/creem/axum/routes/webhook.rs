use super::super::{CreemRouteState, support};
use crate::creem::{CreemWebhookError, decode_creem_webhook_text, process_creem_webhook};
use axum::{Extension, body::to_bytes, extract::Request, response::Response};

pub(super) async fn receive(
    Extension(state): Extension<CreemRouteState>,
    request: Request,
) -> Response {
    let signature = request
        .headers()
        .get("creem-signature")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let Some(secret) = state
        .options
        .webhook_secret
        .as_deref()
        .filter(|secret| !secret.is_empty())
    else {
        return support::error("Webhook secret is not configured");
    };
    let bytes = match to_bytes(request.into_body(), 2 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!(message = %error, "[creem] Failed to process webhook");
            return support::error("Failed to process webhook");
        }
    };
    let payload = decode_creem_webhook_text(&bytes);
    let persistence =
        state.options.persist_subscriptions.then_some(
            state.webhook_persistence.as_ref() as &dyn crate::creem::CreemWebhookPersistence
        );
    match process_creem_webhook(
        &payload,
        signature.as_deref(),
        secret,
        &state.options.callbacks,
        persistence,
    )
    .await
    {
        Ok(()) => support::success(serde_json::json!({"message": "Webhook received"})),
        Err(CreemWebhookError::InvalidSignature) => support::error("Invalid signature"),
        Err(CreemWebhookError::UnknownEventType) => support::error("Unknown event type"),
        Err(CreemWebhookError::ProcessingFailed) => support::error("Failed to process webhook"),
    }
}
