mod event;
mod signature;

pub use event::{DodoWebhookParseError, parse_webhook_payload};
pub use signature::{
    DodoWebhookSignatureError, sign_dodo_webhook, validate_dodo_webhook_signature,
};

use crate::dodo_payments::{DodoWebhookCallbackError, DodoWebhookCallbacks, DodoWebhookEvent};

#[derive(Debug, thiserror::Error)]
pub enum DodoWebhookError {
    #[error(transparent)]
    Signature(#[from] DodoWebhookSignatureError),
    #[error(transparent)]
    Parse(#[from] DodoWebhookParseError),
    #[error(transparent)]
    Callback(#[from] DodoWebhookCallbackError),
}

pub async fn process_dodo_webhook(
    body: &str,
    webhook_id: Option<&str>,
    webhook_timestamp: Option<&str>,
    webhook_signature: Option<&str>,
    secret: &str,
    callbacks: &DodoWebhookCallbacks,
) -> Result<DodoWebhookEvent, DodoWebhookError> {
    validate_dodo_webhook_signature(
        body,
        webhook_id,
        webhook_timestamp,
        webhook_signature,
        secret,
    )?;
    let event = parse_webhook_payload(body)?;
    callbacks.dispatch(&event).await?;
    Ok(event)
}
