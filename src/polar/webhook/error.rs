use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolarWebhookError {
    #[error("Missing required headers")]
    MissingHeader(&'static str),
    #[error("Invalid Signature Headers")]
    InvalidTimestamp,
    #[error("Message timestamp too old")]
    TimestampTooOld,
    #[error("Message timestamp too new")]
    TimestampTooNew,
    #[error("No matching signature found")]
    InvalidSignature,
    #[error("Failed to parse event")]
    InvalidPayload,
    #[error("Failed to parse event")]
    UnsupportedEvent,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PolarWebhookCallbackError {
    message: String,
}

impl PolarWebhookCallbackError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Debug for PolarWebhookCallbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolarWebhookCallbackError")
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for PolarWebhookCallbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PolarWebhookCallbackError {}
