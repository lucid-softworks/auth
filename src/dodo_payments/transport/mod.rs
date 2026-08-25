mod http;
mod types;

pub use http::DodoPaymentsHttpTransport;
pub use types::{
    DodoPaymentsEnvironment, DodoPaymentsHttpMethod, DodoPaymentsProviderConfig,
    DodoPaymentsProviderError, DodoPaymentsTransportRequest,
};

use async_trait::async_trait;
use serde_json::Value;

#[async_trait]
pub trait DodoPaymentsTransport: Send + Sync {
    fn environment(&self) -> DodoPaymentsEnvironment;

    async fn send(
        &self,
        request: DodoPaymentsTransportRequest,
    ) -> Result<Value, DodoPaymentsProviderError>;
}
