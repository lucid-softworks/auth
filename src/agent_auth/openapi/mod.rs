mod handler;
mod parse;
mod preset;
mod response;
#[cfg(test)]
mod test_support;
mod transport;

use std::sync::Arc;

use serde_json::Value;

use crate::{AgentCapability, AgentExecuteHandler};

pub use handler::{
    AgentOpenApiHandlerOptions, AgentOpenApiHeaderResolver, AgentOpenApiHeadersContext,
};
pub use preset::{
    AgentOpenApiApprovalStrength, AgentOpenApiApprovalStrengthResolver, AgentOpenApiCapabilityInfo,
    AgentOpenApiDefaultCapabilities, AgentOpenApiDefaultCapabilityFilter, AgentOpenApiPreset,
    CreateAgentFromOpenApiOptions,
};
pub use transport::{
    AgentOpenApiHttpRequest, AgentOpenApiHttpResponse, AgentOpenApiResponseBody,
    AgentOpenApiTransport, ReqwestAgentOpenApiTransport,
};

pub fn from_openapi(spec: &Value) -> Vec<AgentCapability> {
    parse::parse_capabilities(spec)
        .into_iter()
        .map(|parsed| parsed.capability)
        .collect()
}

pub fn create_openapi_handler(
    spec: &Value,
    options: AgentOpenApiHandlerOptions,
) -> Arc<dyn AgentExecuteHandler> {
    Arc::new(handler::OpenApiExecuteHandler::new(spec, options))
}

pub fn create_from_openapi(
    spec: &Value,
    options: CreateAgentFromOpenApiOptions,
) -> AgentOpenApiPreset {
    preset::create_preset(spec, options)
}
