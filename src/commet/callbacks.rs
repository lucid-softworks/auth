use async_trait::async_trait;
use serde_json::Value;
use std::{fmt, future::Future, sync::Arc};
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct CommetWebhookCallbackError {
    message: String,
}

impl CommetWebhookCallbackError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[async_trait]
pub trait CommetWebhookCallback: Send + Sync {
    async fn call(
        &self,
        payload: SharedCommetWebhookPayload,
    ) -> Result<(), CommetWebhookCallbackError>;
}

pub struct FnCommetWebhookCallback<F>(F);

impl<F> FnCommetWebhookCallback<F> {
    pub fn new(callback: F) -> Self {
        Self(callback)
    }
}

impl<F> fmt::Debug for FnCommetWebhookCallback<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FnCommetWebhookCallback(..)")
    }
}

#[async_trait]
impl<F, Fut> CommetWebhookCallback for FnCommetWebhookCallback<F>
where
    F: Fn(SharedCommetWebhookPayload) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), CommetWebhookCallbackError>> + Send,
{
    async fn call(
        &self,
        payload: SharedCommetWebhookPayload,
    ) -> Result<(), CommetWebhookCallbackError> {
        (self.0)(payload).await
    }
}

pub type SharedCommetWebhookPayload = Arc<Mutex<Value>>;
pub type SharedCommetWebhookCallback = Arc<dyn CommetWebhookCallback>;

#[derive(Clone, Default)]
pub struct CommetWebhookCallbacks {
    pub on_payload: Option<SharedCommetWebhookCallback>,
    pub on_subscription_created: Option<SharedCommetWebhookCallback>,
    pub on_subscription_activated: Option<SharedCommetWebhookCallback>,
    pub on_subscription_canceled: Option<SharedCommetWebhookCallback>,
    pub on_subscription_updated: Option<SharedCommetWebhookCallback>,
    pub on_subscription_plan_changed: Option<SharedCommetWebhookCallback>,
    pub on_payment_received: Option<SharedCommetWebhookCallback>,
    pub on_payment_failed: Option<SharedCommetWebhookCallback>,
    pub on_invoice_created: Option<SharedCommetWebhookCallback>,
}

impl fmt::Debug for CommetWebhookCallbacks {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommetWebhookCallbacks")
            .field("on_payload", &self.on_payload.is_some())
            .field("named_callback_count", &self.named_callback_count())
            .finish()
    }
}

impl CommetWebhookCallbacks {
    fn named_callback_count(&self) -> usize {
        [
            &self.on_subscription_created,
            &self.on_subscription_activated,
            &self.on_subscription_canceled,
            &self.on_subscription_updated,
            &self.on_subscription_plan_changed,
            &self.on_payment_received,
            &self.on_payment_failed,
            &self.on_invoice_created,
        ]
        .into_iter()
        .filter(|callback| callback.is_some())
        .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_exposes_callbacks() {
        let callbacks = CommetWebhookCallbacks {
            on_payload: Some(Arc::new(FnCommetWebhookCallback::new(
                |_: SharedCommetWebhookPayload| async { Ok::<(), CommetWebhookCallbackError>(()) },
            ))),
            on_payment_failed: Some(Arc::new(FnCommetWebhookCallback::new(
                |_: SharedCommetWebhookPayload| async { Ok::<(), CommetWebhookCallbackError>(()) },
            ))),
            ..CommetWebhookCallbacks::default()
        };

        assert_eq!(
            format!("{callbacks:?}"),
            "CommetWebhookCallbacks { on_payload: true, named_callback_count: 1 }"
        );
    }
}
