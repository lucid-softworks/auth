use super::{error::StripeWebhookError, lifecycle};
use crate::stripe::{StripeEvent, StripeOptions, StripeStore};
use std::sync::Arc;

#[derive(Clone)]
pub struct StripeWebhookService {
    options: Arc<StripeOptions>,
    store: Arc<dyn StripeStore>,
}

impl StripeWebhookService {
    pub fn new(options: Arc<StripeOptions>, store: Arc<dyn StripeStore>) -> Self {
        Self { options, store }
    }

    /// Verify and process an untouched webhook payload.
    ///
    /// `None` represents a request without a body. An empty byte slice is a
    /// present raw body and is passed to Stripe's construction boundary.
    pub async fn handle_raw(
        &self,
        payload: Option<&[u8]>,
        signature: Option<&str>,
    ) -> Result<StripeEvent, StripeWebhookError> {
        let payload = payload.ok_or(StripeWebhookError::InvalidRequestBody)?;
        let signature = signature
            .filter(|signature| !signature.is_empty())
            .ok_or(StripeWebhookError::SignatureNotFound)?;
        let secret = self.options.stripe_webhook_secret();
        if secret.is_empty() {
            return Err(StripeWebhookError::WebhookSecretNotFound);
        }

        let event = self
            .options
            .client
            .construct_webhook_event(payload, signature, secret)
            .await
            .map_err(|error| {
                tracing::error!(message = %error, "Stripe webhook event construction failed");
                StripeWebhookError::FailedToConstructEvent
            })?;

        if let Err(error) = lifecycle::run(&self.options, self.store.as_ref(), &event).await {
            tracing::error!("Stripe webhook failed. Error: {error}");
        }
        if let Some(callback) = &self.options.on_event {
            callback.on_event(&event).await.map_err(|error| {
                tracing::error!("Stripe webhook failed. Error: {}", error.message);
                StripeWebhookError::EventCallback
            })?;
        }
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stripe::webhook::test_support::{FakeStripeClient, event};
    use crate::stripe::{
        EventCallback, MemoryStripeStore, StripeCallbackError, StripeEvent, StripeOptions,
    };
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct EventRecorder {
        calls: AtomicUsize,
        fail: bool,
    }

    #[async_trait]
    impl EventCallback for EventRecorder {
        async fn on_event(&self, _event: &StripeEvent) -> Result<(), StripeCallbackError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(StripeCallbackError::new("observer failed"))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn passes_the_untouched_body_signature_and_secret_and_observes_unknown_events() {
        let client = Arc::new(FakeStripeClient::new(event("invoice.paid", json!({}))));
        let recorder = Arc::new(EventRecorder {
            calls: AtomicUsize::new(0),
            fail: false,
        });
        let mut options = StripeOptions::new(client.clone(), "whsec_exact");
        options.on_event = Some(recorder.clone());
        let service = StripeWebhookService::new(options.into(), Arc::new(MemoryStripeStore::new()));

        let handled = service
            .handle_raw(Some(b" {\"raw\": true}\n"), Some("t=1,v1=sig"))
            .await
            .unwrap();

        assert_eq!(handled.event_type, "invoice.paid");
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *client.construction.lock().unwrap(),
            Some((
                b" {\"raw\": true}\n".to_vec(),
                "t=1,v1=sig".into(),
                "whsec_exact".into()
            ))
        );
    }

    #[tokio::test]
    async fn distinguishes_request_construction_and_outer_callback_failures() {
        let client = Arc::new(FakeStripeClient::new(event("unknown", json!({}))));
        let empty_secret = StripeWebhookService::new(
            Arc::new(StripeOptions::new(client.clone(), "")),
            Arc::new(MemoryStripeStore::new()),
        );
        assert_eq!(
            empty_secret.handle_raw(None, Some("sig")).await,
            Err(StripeWebhookError::InvalidRequestBody)
        );
        assert_eq!(
            empty_secret.handle_raw(Some(b"{}"), None).await,
            Err(StripeWebhookError::SignatureNotFound)
        );
        assert_eq!(
            empty_secret.handle_raw(Some(b"{}"), Some("sig")).await,
            Err(StripeWebhookError::WebhookSecretNotFound)
        );

        let mut options = StripeOptions::new(client, "whsec_test");
        options.on_event = Some(Arc::new(EventRecorder {
            calls: AtomicUsize::new(0),
            fail: true,
        }));
        let service = StripeWebhookService::new(options.into(), Arc::new(MemoryStripeStore::new()));
        assert_eq!(
            service.handle_raw(Some(b"{}"), Some("sig")).await,
            Err(StripeWebhookError::EventCallback)
        );
    }
}
