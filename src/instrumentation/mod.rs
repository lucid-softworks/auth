//! Better Auth 1.7.1 OpenTelemetry instrumentation.
//!
//! Instrumentation is automatic and uses the application's global
//! OpenTelemetry provider. This module never installs a provider, exporter,
//! sampler, subscriber, or propagator.

mod attributes;
#[cfg(test)]
mod contract;
mod names;
mod span;
mod store;

pub use attributes::*;
pub use names::{AdapterOperation, DatabaseHookOperation, EndpointSpanMetadata, HookSource};
#[cfg(feature = "axum")]
pub(crate) use span::with_http_handler_span;
pub use span::{
    SpanAttribute, with_span, with_span_async, with_span_result, with_span_result_async,
};
pub(crate) use store::InstrumentedAuthStore;

pub const INSTRUMENTATION_SCOPE: &str = "better-auth";
pub const INSTRUMENTATION_VERSION: &str = "1.7.1";

pub async fn with_adapter_operation<T, E, F>(
    operation: AdapterOperation,
    model: &str,
    future: F,
) -> Result<T, E>
where
    E: std::error::Error + 'static,
    F: std::future::Future<Output = Result<T, E>>,
{
    let (name, attributes) = operation.span(model);
    with_span_result_async(name, attributes, future).await
}

pub async fn with_database_hook<T, E, F>(
    operation: DatabaseHookOperation,
    model: &str,
    source: HookSource<'_>,
    future: F,
) -> Result<T, E>
where
    E: std::error::Error + 'static,
    F: std::future::Future<Output = Result<T, E>>,
{
    let (name, attributes) = operation.span(model, source);
    with_span_result_async(name, attributes, future).await
}
