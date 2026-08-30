use crate::instrumentation::{
    ATTR_HTTP_RESPONSE_STATUS_CODE, INSTRUMENTATION_SCOPE, INSTRUMENTATION_VERSION,
};
use futures_util::FutureExt as CatchUnwindFutureExt;
use opentelemetry::{
    Context, InstrumentationScope, KeyValue, global,
    trace::{FutureExt, Status, TraceContextExt, Tracer},
};
use std::{
    any::Any,
    borrow::Cow,
    error::Error,
    fmt,
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
};

#[derive(Debug, Clone, PartialEq)]
pub struct SpanAttribute {
    key: Cow<'static, str>,
    value: opentelemetry::Value,
}

impl SpanAttribute {
    pub fn string(key: &'static str, value: impl Into<String>) -> Self {
        Self {
            key: Cow::Borrowed(key),
            value: opentelemetry::Value::String(value.into().into()),
        }
    }

    pub fn integer(key: &'static str, value: i64) -> Self {
        Self {
            key: Cow::Borrowed(key),
            value: opentelemetry::Value::I64(value),
        }
    }
}

pub fn with_span<T>(
    name: impl Into<Cow<'static, str>>,
    attributes: impl IntoIterator<Item = SpanAttribute>,
    callback: impl FnOnce() -> T,
) -> T {
    let span = span(name, attributes);
    let context = Context::current_with_span(span);
    let _guard = context.clone().attach();
    match catch_unwind(AssertUnwindSafe(callback)) {
        Ok(result) => {
            context.span().end();
            result
        }
        Err(panic) => {
            finish_panic(&context, panic.as_ref());
            resume_unwind(panic)
        }
    }
}

pub fn with_span_result<T, E>(
    name: impl Into<Cow<'static, str>>,
    attributes: impl IntoIterator<Item = SpanAttribute>,
    callback: impl FnOnce() -> Result<T, E>,
) -> Result<T, E>
where
    E: Error + 'static,
{
    let span = span(name, attributes);
    let context = Context::current_with_span(span);
    let _guard = context.clone().attach();
    match catch_unwind(AssertUnwindSafe(callback)) {
        Ok(result) => {
            finish(&context, &result);
            result
        }
        Err(panic) => {
            finish_panic(&context, panic.as_ref());
            resume_unwind(panic)
        }
    }
}

pub async fn with_span_async<T, F>(
    name: impl Into<Cow<'static, str>>,
    attributes: impl IntoIterator<Item = SpanAttribute>,
    future: F,
) -> T
where
    F: Future<Output = T>,
{
    let span = span(name, attributes);
    let context = Context::current_with_span(span);
    match AssertUnwindSafe(future.with_context(context.clone()))
        .catch_unwind()
        .await
    {
        Ok(result) => {
            context.span().end();
            result
        }
        Err(panic) => {
            finish_panic(&context, panic.as_ref());
            resume_unwind(panic)
        }
    }
}

pub async fn with_span_result_async<T, E, F>(
    name: impl Into<Cow<'static, str>>,
    attributes: impl IntoIterator<Item = SpanAttribute>,
    future: F,
) -> Result<T, E>
where
    E: Error + 'static,
    F: Future<Output = Result<T, E>>,
{
    let span = span(name, attributes);
    let context = Context::current_with_span(span);
    match AssertUnwindSafe(future.with_context(context.clone()))
        .catch_unwind()
        .await
    {
        Ok(result) => {
            finish(&context, &result);
            result
        }
        Err(panic) => {
            finish_panic(&context, panic.as_ref());
            resume_unwind(panic)
        }
    }
}

#[cfg(feature = "axum")]
pub(crate) async fn with_http_handler_span<F>(
    name: impl Into<Cow<'static, str>>,
    attributes: impl IntoIterator<Item = SpanAttribute>,
    future: F,
) -> axum::response::Response
where
    F: Future<Output = axum::response::Response>,
{
    let span = span(name, attributes);
    let context = Context::current_with_span(span);
    match AssertUnwindSafe(future.with_context(context.clone()))
        .catch_unwind()
        .await
    {
        Ok(response) => {
            if let Some(error) = response.extensions().get::<crate::axum::ApiErrorResponse>() {
                let status = response.status().as_u16();
                if (300..400).contains(&status) {
                    let span = context.span();
                    span.set_attribute(KeyValue::new(
                        ATTR_HTTP_RESPONSE_STATUS_CODE,
                        i64::from(status),
                    ));
                    span.set_status(Status::Ok);
                } else {
                    finish_response_error(&context, &error.message);
                    return response;
                }
            }
            context.span().end();
            response
        }
        Err(panic) => {
            finish_panic(&context, panic.as_ref());
            resume_unwind(panic)
        }
    }
}

fn span(
    name: impl Into<Cow<'static, str>>,
    attributes: impl IntoIterator<Item = SpanAttribute>,
) -> opentelemetry::global::BoxedSpan {
    let attributes = attributes
        .into_iter()
        .map(|attribute| KeyValue::new(attribute.key, attribute.value))
        .collect::<Vec<_>>();
    let scope = InstrumentationScope::builder(INSTRUMENTATION_SCOPE)
        .with_version(INSTRUMENTATION_VERSION)
        .build();
    let tracer = global::tracer_with_scope(scope);
    tracer
        .span_builder(name)
        .with_attributes(attributes)
        .start(&tracer)
}

fn finish<T, E>(context: &Context, result: &Result<T, E>)
where
    E: Error + 'static,
{
    let span = context.span();
    if let Err(error) = result {
        if let Some(status) = redirect_status_code(error) {
            span.set_attribute(KeyValue::new(
                ATTR_HTTP_RESPONSE_STATUS_CODE,
                i64::from(status),
            ));
            span.set_status(Status::Ok);
        } else {
            span.record_error(error);
            span.set_status(Status::error(error.to_string()));
        }
    }
    span.end();
}

fn redirect_status_code(error: &(dyn Error + 'static)) -> Option<u16> {
    let status = if let Some(error) = error.downcast_ref::<crate::PluginApiError>() {
        Some(error.status)
    } else if let Some(crate::AuthError::PluginApi(error)) =
        error.downcast_ref::<crate::AuthError>()
    {
        Some(error.status)
    } else {
        None
    };
    status.filter(|status| (300..400).contains(status))
}

fn finish_panic(context: &Context, panic: &(dyn Any + Send)) {
    let message = panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("Rust panic");
    let error = PanicError(message.to_owned());
    let span = context.span();
    span.record_error(&error);
    span.set_status(Status::error(message.to_owned()));
    span.end();
}

#[cfg(feature = "axum")]
fn finish_response_error(context: &Context, message: &str) {
    let error = PanicError(message.to_owned());
    let span = context.span();
    span.record_error(&error);
    span.set_status(Status::error(message.to_owned()));
    span.end();
}

#[derive(Debug)]
struct PanicError(String);

impl fmt::Display for PanicError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for PanicError {}
