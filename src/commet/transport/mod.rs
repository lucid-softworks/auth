mod http;
mod types;

pub use http::CommetHttpTransport;
pub use types::{
    CommetHttpMethod, CommetProviderConfig, CommetProviderError, CommetTransportRequest,
};

use async_trait::async_trait;
use serde_json::Value;

#[async_trait]
pub trait CommetTransport: Send + Sync {
    async fn send(&self, request: CommetTransportRequest) -> Result<Value, CommetProviderError>;
}
