use super::validate_commet_webhook_signature;
use crate::commet::{
    CommetWebhookCallbackError, CommetWebhookCallbacks, SharedCommetWebhookPayload,
};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum CommetWebhookError {
    #[error("Invalid webhook signature")]
    InvalidSignature,
    #[error("Webhook handler error")]
    Handler(#[source] CommetWebhookCallbackError),
}

pub fn parse_verified_payload(
    body: &str,
    signature: Option<&str>,
    secret: &str,
) -> Result<Value, CommetWebhookError> {
    if !validate_commet_webhook_signature(body, signature, secret) {
        return Err(CommetWebhookError::InvalidSignature);
    }
    let payload: Value =
        serde_json::from_str(body).map_err(|_| CommetWebhookError::InvalidSignature)?;
    if !javascript_truthy(&payload) {
        return Err(CommetWebhookError::InvalidSignature);
    }
    Ok(payload)
}

pub async fn process_commet_webhook(
    body: &str,
    signature: Option<&str>,
    secret: &str,
    callbacks: &CommetWebhookCallbacks,
) -> Result<Value, CommetWebhookError> {
    let payload = Arc::new(Mutex::new(parse_verified_payload(body, signature, secret)?));
    dispatch(payload.clone(), callbacks)
        .await
        .map_err(CommetWebhookError::Handler)?;
    let final_payload = payload.lock().await.clone();
    Ok(final_payload)
}

async fn dispatch(
    payload: SharedCommetWebhookPayload,
    callbacks: &CommetWebhookCallbacks,
) -> Result<(), CommetWebhookCallbackError> {
    let event = payload
        .lock()
        .await
        .get("event")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let named = event
        .as_deref()
        .and_then(|event| named_callback(event, callbacks));
    if let Some(callback) = named {
        callback.call(payload.clone()).await?;
    }
    if let Some(callback) = &callbacks.on_payload {
        callback.call(payload).await?;
    }
    Ok(())
}

fn named_callback<'a>(
    event: &str,
    callbacks: &'a CommetWebhookCallbacks,
) -> Option<&'a crate::commet::SharedCommetWebhookCallback> {
    match event {
        "subscription.created" => callbacks.on_subscription_created.as_ref(),
        "subscription.activated" => callbacks.on_subscription_activated.as_ref(),
        "subscription.canceled" => callbacks.on_subscription_canceled.as_ref(),
        "subscription.updated" => callbacks.on_subscription_updated.as_ref(),
        "subscription.plan_changed" => callbacks.on_subscription_plan_changed.as_ref(),
        "payment.received" => callbacks.on_payment_received.as_ref(),
        "payment.failed" => callbacks.on_payment_failed.as_ref(),
        "invoice.created" => callbacks.on_invoice_created.as_ref(),
        _ => None,
    }
}

fn javascript_truthy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Bool(true) | Value::Array(_) | Value::Object(_) => true,
    }
}

#[cfg(test)]
mod contract_tests;
