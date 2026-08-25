mod dispatch;
mod lifecycle;
mod registry;
mod source;

use super::{
    ChargebeeCallbackError, ChargebeeOptions, ChargebeeStore, ChargebeeStoreError,
    ChargebeeWebhookEvent,
};
use std::sync::Arc;

pub use source::{ChargebeeWebhookProcessorSource, ChargebeeWebhookProcessorSourceError};

pub const CHARGEBEE_WEBHOOK_EVENT_TYPES: [&str; 8] = [
    "subscription_created",
    "subscription_activated",
    "subscription_started",
    "subscription_changed",
    "subscription_renewed",
    "subscription_scheduled_cancellation_removed",
    "subscription_cancelled",
    "customer_deleted",
];

#[derive(Debug, thiserror::Error)]
pub enum ChargebeeWebhookProcessingError {
    #[error("Failed to queue webhook event")]
    QueuePublish {
        #[source]
        source: ChargebeeCallbackError,
    },
    #[error("Chargebee custom webhook listener failed for `{event_type}`")]
    CustomListener {
        event_type: String,
        #[source]
        source: ChargebeeCallbackError,
    },
    #[error("Chargebee customer-deleted webhook failed")]
    CustomerDeleted {
        #[source]
        source: ChargebeeStoreError,
    },
    #[error("Failed to resolve Chargebee webhook processor source")]
    SourceResolution {
        #[source]
        source: ChargebeeWebhookProcessorSourceError,
    },
}

/// Handles one parsed webhook event at the synchronous HTTP boundary.
///
/// A listener registry is reconstructed for every event, matching the package's
/// per-request Chargebee handler construction. Provider event-bus persistence,
/// built-in transitions, and application listeners are all awaited.
pub struct ChargebeeWebhookDispatcher {
    options: Arc<ChargebeeOptions>,
    store: Arc<dyn ChargebeeStore>,
}

impl ChargebeeWebhookDispatcher {
    pub fn new(options: Arc<ChargebeeOptions>, store: Arc<dyn ChargebeeStore>) -> Self {
        Self { options, store }
    }

    pub async fn handle(
        &self,
        event: ChargebeeWebhookEvent,
    ) -> Result<(), ChargebeeWebhookProcessingError> {
        let listeners = registry::ListenerRegistry::from_options(&self.options);
        let known = is_known_event(&event.event_type);
        let reserved_unhandled = event.event_type == "unhandled_event";
        let has_exact_listener = listeners.has(&event.event_type);

        if let Some(event_bus) = &self.options.webhook_event_bus {
            if known || reserved_unhandled || !has_exact_listener {
                event_bus.publish(event.clone()).await.map_err(|source| {
                    tracing::error!(%source, "Failed to queue Chargebee webhook event");
                    ChargebeeWebhookProcessingError::QueuePublish {
                        source: ChargebeeCallbackError::new("Failed to queue webhook event"),
                    }
                })?;
            }
        } else if known {
            dispatch::built_in(&self.options, self.store.as_ref(), &event).await?;
        } else if reserved_unhandled || !has_exact_listener {
            tracing::info!(
                event_type = %event.event_type,
                "Unhandled Chargebee webhook event"
            );
        }

        if has_exact_listener {
            listeners.call(&event.event_type, &event).await?;
        } else if !known {
            listeners.call("unhandled_event", &event).await?;
        }
        Ok(())
    }
}

/// Processes events previously persisted by `ChargebeeWebhookEventBus`.
///
/// Custom endpoint listeners are intentionally excluded: the published queued
/// processor runs only the built-in database synchronization mappings.
pub struct ChargebeeWebhookProcessor {
    options: Arc<ChargebeeOptions>,
    source: Arc<dyn ChargebeeWebhookProcessorSource>,
}

impl ChargebeeWebhookProcessor {
    pub fn new(options: Arc<ChargebeeOptions>, store: Arc<dyn ChargebeeStore>) -> Self {
        Self::with_source(
            options,
            Arc::new(source::FixedChargebeeWebhookProcessorSource::new(store)),
        )
    }

    pub fn with_source(
        options: Arc<ChargebeeOptions>,
        source: Arc<dyn ChargebeeWebhookProcessorSource>,
    ) -> Self {
        Self { options, source }
    }

    pub async fn process(
        &self,
        event: &ChargebeeWebhookEvent,
    ) -> Result<(), ChargebeeWebhookProcessingError> {
        let store = self
            .source
            .resolve()
            .await
            .map_err(|source| ChargebeeWebhookProcessingError::SourceResolution { source })?;
        dispatch::built_in(&self.options, store.as_ref(), event).await
    }
}

fn is_known_event(event_type: &str) -> bool {
    CHARGEBEE_WEBHOOK_EVENT_TYPES.contains(&event_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthStore, MemoryChargebeeStore, MemoryStore};
    use async_trait::async_trait;
    use serde_json::json;
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct CountingSource {
        calls: AtomicUsize,
        store: Arc<dyn ChargebeeStore>,
    }

    #[async_trait]
    impl ChargebeeWebhookProcessorSource for CountingSource {
        async fn resolve(
            &self,
        ) -> Result<Arc<dyn ChargebeeStore>, ChargebeeWebhookProcessorSourceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::clone(&self.store))
        }
    }

    struct FailingSource;

    struct FailingEventBus;

    #[async_trait]
    impl crate::chargebee::ChargebeeWebhookEventBus for FailingEventBus {
        async fn publish(&self, _: ChargebeeWebhookEvent) -> Result<(), ChargebeeCallbackError> {
            Err(ChargebeeCallbackError::new("private queue failure"))
        }
    }

    #[async_trait]
    impl ChargebeeWebhookProcessorSource for FailingSource {
        async fn resolve(
            &self,
        ) -> Result<Arc<dyn ChargebeeStore>, ChargebeeWebhookProcessorSourceError> {
            Err(ChargebeeWebhookProcessorSourceError::new(
                "auth context unavailable",
            ))
        }
    }

    fn options() -> Arc<ChargebeeOptions> {
        Arc::new(ChargebeeOptions::new(Arc::new(
            crate::chargebee::test_support::UnavailableClient,
        )))
    }

    fn store() -> Arc<dyn ChargebeeStore> {
        let auth: Arc<dyn AuthStore> = Arc::new(MemoryStore::default());
        Arc::new(MemoryChargebeeStore::new(auth))
    }

    fn unhandled_event() -> ChargebeeWebhookEvent {
        ChargebeeWebhookEvent {
            event_type: "unhandled_oracle".into(),
            id: json!("event_1"),
            content: json!({}),
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn event_set_matches_the_executable_adapter() {
        assert_eq!(CHARGEBEE_WEBHOOK_EVENT_TYPES.len(), 8);
        assert!(is_known_event(
            "subscription_scheduled_cancellation_removed"
        ));
        assert!(!is_known_event("subscription_cancellation_scheduled"));
    }

    #[tokio::test]
    async fn lazy_processor_source_is_resolved_for_every_event() {
        let source = Arc::new(CountingSource {
            calls: AtomicUsize::new(0),
            store: store(),
        });
        let processor = ChargebeeWebhookProcessor::with_source(
            options(),
            Arc::clone(&source) as Arc<dyn ChargebeeWebhookProcessorSource>,
        );

        processor.process(&unhandled_event()).await.unwrap();
        processor.process(&unhandled_event()).await.unwrap();

        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn processor_reports_lazy_source_resolution_failures() {
        let processor = ChargebeeWebhookProcessor::with_source(options(), Arc::new(FailingSource));

        let error = processor.process(&unhandled_event()).await.unwrap_err();

        assert_eq!(
            error.to_string(),
            "Failed to resolve Chargebee webhook processor source"
        );
        assert!(matches!(
            error,
            ChargebeeWebhookProcessingError::SourceResolution { source }
                if source.message == "auth context unavailable"
        ));
    }

    #[tokio::test]
    async fn queue_failure_exposes_only_the_published_message() {
        let mut configured =
            ChargebeeOptions::new(Arc::new(crate::chargebee::test_support::UnavailableClient));
        configured.webhook_event_bus = Some(Arc::new(FailingEventBus));
        let dispatcher = ChargebeeWebhookDispatcher::new(Arc::new(configured), store());

        let error = dispatcher.handle(unhandled_event()).await.unwrap_err();

        assert_eq!(error.to_string(), "Failed to queue webhook event");
        assert!(matches!(
            error,
            ChargebeeWebhookProcessingError::QueuePublish { source }
                if source.message == "Failed to queue webhook event"
        ));
    }
}
