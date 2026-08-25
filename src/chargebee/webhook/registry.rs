use super::ChargebeeWebhookProcessingError;
use crate::chargebee::{
    ChargebeeOptions, ChargebeeWebhookEvent, ChargebeeWebhookListener, ChargebeeWebhookRegistrar,
};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Default)]
pub(super) struct ListenerRegistry {
    listeners: BTreeMap<String, Vec<Arc<dyn ChargebeeWebhookListener>>>,
}

impl ListenerRegistry {
    pub(super) fn from_options(options: &ChargebeeOptions) -> Self {
        let mut registry = Self::default();
        if let Some(handler) = &options.webhook_handler {
            handler.configure(&mut registry);
        }
        registry
    }

    pub(super) fn has(&self, event_type: &str) -> bool {
        self.listeners
            .get(event_type)
            .is_some_and(|listeners| !listeners.is_empty())
    }

    pub(super) async fn call(
        &self,
        event_type: &str,
        event: &ChargebeeWebhookEvent,
    ) -> Result<(), ChargebeeWebhookProcessingError> {
        let Some(listeners) = self.listeners.get(event_type) else {
            return Ok(());
        };
        for listener in listeners {
            listener.call(event).await.map_err(|source| {
                ChargebeeWebhookProcessingError::CustomListener {
                    event_type: event_type.to_owned(),
                    source,
                }
            })?;
        }
        Ok(())
    }
}

impl ChargebeeWebhookRegistrar for ListenerRegistry {
    fn on(&mut self, event_type: String, listener: Arc<dyn ChargebeeWebhookListener>) {
        self.listeners.entry(event_type).or_default().push(listener);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chargebee::{ChargebeeCallbackError, ChargebeeWebhookEvent};
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingListener(Arc<AtomicUsize>);

    struct FailingListener;

    #[async_trait]
    impl ChargebeeWebhookListener for CountingListener {
        async fn call(&self, _: &ChargebeeWebhookEvent) -> Result<(), ChargebeeCallbackError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[async_trait]
    impl ChargebeeWebhookListener for FailingListener {
        async fn call(&self, _: &ChargebeeWebhookEvent) -> Result<(), ChargebeeCallbackError> {
            Err(ChargebeeCallbackError::new("listener failed"))
        }
    }

    #[tokio::test]
    async fn listeners_keep_registration_order_and_repeat() {
        let count = Arc::new(AtomicUsize::new(0));
        let mut registry = ListenerRegistry::default();
        registry.on(
            "custom".into(),
            Arc::new(CountingListener(Arc::clone(&count))),
        );
        registry.on(
            "custom".into(),
            Arc::new(CountingListener(Arc::clone(&count))),
        );
        let event = serde_json::from_value(json!({
            "event_type": "custom",
            "id": 1,
            "content": {}
        }))
        .unwrap();
        registry.call("custom", &event).await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn awaited_listener_failure_stops_later_listeners() {
        let count = Arc::new(AtomicUsize::new(0));
        let mut registry = ListenerRegistry::default();
        registry.on("custom".into(), Arc::new(FailingListener));
        registry.on(
            "custom".into(),
            Arc::new(CountingListener(Arc::clone(&count))),
        );
        let event = serde_json::from_value(json!({
            "event_type": "custom",
            "id": 1,
            "content": {}
        }))
        .unwrap();
        assert!(matches!(
            registry.call("custom", &event).await,
            Err(ChargebeeWebhookProcessingError::CustomListener { .. })
        ));
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
}
