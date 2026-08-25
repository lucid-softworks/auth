use super::*;
use futures_util::FutureExt;
use opentelemetry::{Value, global, trace::Status};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::OnceLock,
};

#[derive(Debug, thiserror::Error)]
#[error("arbitrary failure")]
struct ArbitraryError;

#[cfg(feature = "axum")]
mod http;

fn exporter() -> &'static InMemorySpanExporter {
    static EXPORTER: OnceLock<InMemorySpanExporter> = OnceLock::new();
    EXPORTER.get_or_init(|| {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        global::set_tracer_provider(provider);
        exporter
    })
}

fn find(name: &str) -> SpanData {
    exporter()
        .get_finished_spans()
        .unwrap()
        .into_iter()
        .find(|span| span.name == name)
        .unwrap_or_else(|| panic!("missing span {name}"))
}

#[test]
fn success_preserves_values_scope_and_attributes() {
    let _ = exporter();
    assert_eq!(
        with_span(
            "otel-contract-success",
            [SpanAttribute::string(ATTR_HTTP_ROUTE, "/safe/:id")],
            || 7,
        ),
        7
    );
    let span = find("otel-contract-success");
    assert_eq!(span.status, Status::Unset);
    assert_eq!(span.span_kind, opentelemetry::trace::SpanKind::Internal);
    assert_eq!(span.instrumentation_scope.name(), INSTRUMENTATION_SCOPE);
    assert_eq!(
        span.instrumentation_scope.version(),
        Some(INSTRUMENTATION_VERSION)
    );
    assert_eq!(span.attributes.len(), 1);
    assert_eq!(span.attributes[0].key.as_str(), ATTR_HTTP_ROUTE);
}

#[tokio::test]
async fn errors_redirects_panics_and_cancellation_match_completion_rules() {
    let _ = exporter();
    assert!(
        with_span_result("otel-contract-error", [], || {
            Err::<(), _>(ArbitraryError)
        })
        .is_err()
    );
    assert!(
        with_span_result("otel-contract-redirect", [], || {
            Err::<(), _>(crate::PluginApiError::new(302, "FOUND", "redirect"))
        })
        .is_err()
    );
    let panic = catch_unwind(AssertUnwindSafe(|| {
        with_span("otel-contract-sync-panic", [], || panic!("sync panic"));
    }));
    assert!(panic.is_err());
    let async_panic = AssertUnwindSafe(with_span_async("otel-contract-async-panic", [], async {
        panic!("async panic")
    }))
    .catch_unwind()
    .await;
    assert!(async_panic.is_err());
    let cancelled = tokio::spawn(with_span_async(
        "otel-contract-cancelled",
        [],
        std::future::pending::<()>(),
    ));
    tokio::task::yield_now().await;
    cancelled.abort();
    let _ = cancelled.await;

    assert_eq!(
        find("otel-contract-error").status,
        Status::error("arbitrary failure")
    );
    assert_eq!(find("otel-contract-error").events.len(), 1);
    let redirect = find("otel-contract-redirect");
    assert_eq!(redirect.status, Status::Ok);
    assert!(redirect.events.is_empty());
    assert!(redirect.attributes.iter().any(|item| {
        item.key.as_str() == ATTR_HTTP_RESPONSE_STATUS_CODE && item.value == Value::I64(302)
    }));
    assert_eq!(find("otel-contract-sync-panic").events.len(), 1);
    assert_eq!(find("otel-contract-async-panic").events.len(), 1);
    assert_eq!(find("otel-contract-cancelled").status, Status::Unset);
}

#[tokio::test]
async fn adapter_and_database_hook_boundaries_emit_every_exact_family() {
    let _ = exporter();
    let operations = [
        AdapterOperation::Create,
        AdapterOperation::FindOne,
        AdapterOperation::FindMany,
        AdapterOperation::Update,
        AdapterOperation::UpdateMany,
        AdapterOperation::Delete,
        AdapterOperation::DeleteMany,
        AdapterOperation::ConsumeOne,
        AdapterOperation::IncrementOne,
        AdapterOperation::Count,
    ];
    for operation in operations {
        with_adapter_operation(operation, "contractModel", async {
            Ok::<_, ArbitraryError>(())
        })
        .await
        .unwrap();
        let span = find(&format!("db {} contractModel", operation.as_str()));
        assert_eq!(span.status, Status::Unset);
        assert_eq!(span.attributes.len(), 2);
    }

    let hooks = [
        DatabaseHookOperation::CreateBefore,
        DatabaseHookOperation::CreateAfter,
        DatabaseHookOperation::UpdateBefore,
        DatabaseHookOperation::UpdateAfter,
        DatabaseHookOperation::UpdateManyBefore,
        DatabaseHookOperation::UpdateManyAfter,
        DatabaseHookOperation::DeleteBefore,
        DatabaseHookOperation::DeleteAfter,
    ];
    for operation in hooks {
        with_database_hook(
            operation,
            "contractModel",
            HookSource::Plugin("contract"),
            async { Ok::<_, ArbitraryError>(()) },
        )
        .await
        .unwrap();
        let span = find(&format!("db {} contractModel", operation.as_str()));
        assert_eq!(span.attributes.len(), 3);
    }
}

#[tokio::test]
async fn nested_async_spans_retain_parentage() {
    let _ = exporter();
    with_span_async("otel-contract-parent", [], async {
        with_span_async("otel-contract-child", [], async {}).await;
    })
    .await;
    let parent = find("otel-contract-parent");
    let child = find("otel-contract-child");
    assert_eq!(child.parent_span_id, parent.span_context.span_id());
}
