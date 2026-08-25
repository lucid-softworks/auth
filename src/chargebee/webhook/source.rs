use crate::chargebee::ChargebeeStore;
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ChargebeeWebhookProcessorSourceError {
    pub message: String,
}

impl ChargebeeWebhookProcessorSourceError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Resolves the persistence context for one queued Chargebee webhook.
///
/// Implementations may return a fixed store or lazily obtain one from an
/// application auth context. `resolve` is called for every `process` request.
#[async_trait]
pub trait ChargebeeWebhookProcessorSource: Send + Sync {
    async fn resolve(
        &self,
    ) -> Result<Arc<dyn ChargebeeStore>, ChargebeeWebhookProcessorSourceError>;
}

pub(super) struct FixedChargebeeWebhookProcessorSource {
    store: Arc<dyn ChargebeeStore>,
}

impl FixedChargebeeWebhookProcessorSource {
    pub(super) fn new(store: Arc<dyn ChargebeeStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl ChargebeeWebhookProcessorSource for FixedChargebeeWebhookProcessorSource {
    async fn resolve(
        &self,
    ) -> Result<Arc<dyn ChargebeeStore>, ChargebeeWebhookProcessorSourceError> {
        Ok(Arc::clone(&self.store))
    }
}
