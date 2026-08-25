use async_trait::async_trait;
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct CreemPersistenceError {
    message: String,
}

impl CreemPersistenceError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[async_trait]
pub trait CreemWebhookPersistence: Send + Sync {
    async fn persist_checkout(
        &self,
        checkout: &Map<String, Value>,
    ) -> Result<(), CreemPersistenceError>;

    async fn persist_subscription(
        &self,
        event_type: &str,
        subscription: &Map<String, Value>,
    ) -> Result<(), CreemPersistenceError>;

    async fn mark_trial(
        &self,
        subscription: &Map<String, Value>,
    ) -> Result<(), CreemPersistenceError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoopCreemWebhookPersistence;

#[async_trait]
impl CreemWebhookPersistence for NoopCreemWebhookPersistence {
    async fn persist_checkout(
        &self,
        _checkout: &Map<String, Value>,
    ) -> Result<(), CreemPersistenceError> {
        Ok(())
    }

    async fn persist_subscription(
        &self,
        _event_type: &str,
        _subscription: &Map<String, Value>,
    ) -> Result<(), CreemPersistenceError> {
        Ok(())
    }

    async fn mark_trial(
        &self,
        _subscription: &Map<String, Value>,
    ) -> Result<(), CreemPersistenceError> {
        Ok(())
    }
}
