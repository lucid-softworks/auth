use async_trait::async_trait;
use serde_json::Value;
use std::{fmt, future::Future, sync::Arc};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct CreemCallbackError {
    message: String,
}

impl CreemCallbackError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[async_trait]
pub trait CreemWebhookCallback: Send + Sync {
    async fn call(&self, payload: Value) -> Result<(), CreemCallbackError>;
}

pub struct FnCreemWebhookCallback<F>(F);

impl<F> FnCreemWebhookCallback<F> {
    pub fn new(callback: F) -> Self {
        Self(callback)
    }
}

impl<F> fmt::Debug for FnCreemWebhookCallback<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FnCreemWebhookCallback(..)")
    }
}

#[async_trait]
impl<F, Fut> CreemWebhookCallback for FnCreemWebhookCallback<F>
where
    F: Fn(Value) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), CreemCallbackError>> + Send,
{
    async fn call(&self, payload: Value) -> Result<(), CreemCallbackError> {
        (self.0)(payload).await
    }
}

pub struct SyncCreemWebhookCallback<F>(F);

impl<F> SyncCreemWebhookCallback<F> {
    pub fn new(callback: F) -> Self {
        Self(callback)
    }
}

impl<F> fmt::Debug for SyncCreemWebhookCallback<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SyncCreemWebhookCallback(..)")
    }
}

#[async_trait]
impl<F> CreemWebhookCallback for SyncCreemWebhookCallback<F>
where
    F: Fn(Value) -> Result<(), CreemCallbackError> + Send + Sync,
{
    async fn call(&self, payload: Value) -> Result<(), CreemCallbackError> {
        (self.0)(payload)
    }
}

#[derive(Clone, Default)]
pub struct CreemWebhookCallbacks {
    pub on_checkout_completed: Option<Arc<dyn CreemWebhookCallback>>,
    pub on_refund_created: Option<Arc<dyn CreemWebhookCallback>>,
    pub on_dispute_created: Option<Arc<dyn CreemWebhookCallback>>,
    pub on_subscription_active: Option<Arc<dyn CreemWebhookCallback>>,
    pub on_subscription_trialing: Option<Arc<dyn CreemWebhookCallback>>,
    pub on_subscription_canceled: Option<Arc<dyn CreemWebhookCallback>>,
    pub on_subscription_paid: Option<Arc<dyn CreemWebhookCallback>>,
    pub on_subscription_expired: Option<Arc<dyn CreemWebhookCallback>>,
    pub on_subscription_unpaid: Option<Arc<dyn CreemWebhookCallback>>,
    pub on_subscription_update: Option<Arc<dyn CreemWebhookCallback>>,
    pub on_subscription_past_due: Option<Arc<dyn CreemWebhookCallback>>,
    pub on_subscription_paused: Option<Arc<dyn CreemWebhookCallback>>,
    pub on_grant_access: Option<Arc<dyn CreemWebhookCallback>>,
    pub on_revoke_access: Option<Arc<dyn CreemWebhookCallback>>,
}

impl fmt::Debug for CreemWebhookCallbacks {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreemWebhookCallbacks")
            .field(
                "on_checkout_completed",
                &self.on_checkout_completed.is_some(),
            )
            .field("on_refund_created", &self.on_refund_created.is_some())
            .field("on_dispute_created", &self.on_dispute_created.is_some())
            .field(
                "on_subscription_active",
                &self.on_subscription_active.is_some(),
            )
            .field(
                "on_subscription_trialing",
                &self.on_subscription_trialing.is_some(),
            )
            .field(
                "on_subscription_canceled",
                &self.on_subscription_canceled.is_some(),
            )
            .field("on_subscription_paid", &self.on_subscription_paid.is_some())
            .field(
                "on_subscription_expired",
                &self.on_subscription_expired.is_some(),
            )
            .field(
                "on_subscription_unpaid",
                &self.on_subscription_unpaid.is_some(),
            )
            .field(
                "on_subscription_update",
                &self.on_subscription_update.is_some(),
            )
            .field(
                "on_subscription_past_due",
                &self.on_subscription_past_due.is_some(),
            )
            .field(
                "on_subscription_paused",
                &self.on_subscription_paused.is_some(),
            )
            .field("on_grant_access", &self.on_grant_access.is_some())
            .field("on_revoke_access", &self.on_revoke_access.is_some())
            .finish()
    }
}
