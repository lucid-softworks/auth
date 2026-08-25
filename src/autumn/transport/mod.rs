mod http;
mod types;

pub use http::AutumnHttpClient;
pub use types::{AutumnOperation, AutumnProviderError};

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

/// Injectable in-process boundary for the fifteen calls made by
/// `autumn-js@1.2.53`'s Better Auth adapter.
#[async_trait]
pub trait AutumnClient: Send + Sync {
    /// Validate, encode, and execute one Autumn SDK operation.
    async fn execute(
        &self,
        operation: AutumnOperation,
        request: Value,
        secret_key: &str,
        base_url: &Url,
    ) -> Result<Value, AutumnProviderError>;
}
