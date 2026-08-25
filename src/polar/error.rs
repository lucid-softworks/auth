use crate::{AuthError, PluginApiError};

pub const POLAR_ADAPTER_VERSION: &str = "1.8.4";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct PolarCallbackError {
    pub message: String,
}

impl PolarCallbackError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub(crate) fn customer_creation_error(error: impl std::fmt::Display) -> AuthError {
    PluginApiError::new(
        500,
        "INTERNAL_SERVER_ERROR",
        format!("Polar customer creation failed. Error: {error}"),
    )
    .into()
}
