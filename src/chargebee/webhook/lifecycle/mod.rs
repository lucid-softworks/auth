pub(super) mod complete;
pub(super) mod created;
pub(super) mod customer;
pub(super) mod deleted;
mod mapping;
pub(super) mod updated;

use crate::chargebee::{ChargebeeCallbackError, ChargebeeStoreError};

#[derive(Debug, thiserror::Error)]
enum LifecycleError {
    #[error(transparent)]
    Store(#[from] ChargebeeStoreError),
    #[error(transparent)]
    Callback(#[from] ChargebeeCallbackError),
    #[error("invalid Chargebee timestamp `{0}`")]
    InvalidTimestamp(i64),
}

fn log_failure(error: &LifecycleError) {
    tracing::error!(message = %error, "Chargebee webhook failed");
}
