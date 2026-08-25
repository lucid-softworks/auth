use super::{
    CreemWebhookEvent, CreemWebhookPersistence, parse_webhook_event, validate_webhook_signature,
};
use crate::creem::{CreemCallbackError, CreemWebhookCallback, CreemWebhookCallbacks};
use serde_json::{Map, Value};

const HANDLED_EVENTS: &[&str] = &[
    "checkout.completed",
    "refund.created",
    "dispute.created",
    "subscription.active",
    "subscription.trialing",
    "subscription.canceled",
    "subscription.paid",
    "subscription.expired",
    "subscription.unpaid",
    "subscription.update",
    "subscription.past_due",
    "subscription.paused",
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CreemWebhookError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Unknown event type")]
    UnknownEventType,
    #[error("Failed to process webhook")]
    ProcessingFailed,
}

pub async fn process_webhook(
    payload: &str,
    signature: Option<&str>,
    secret: &str,
    callbacks: &CreemWebhookCallbacks,
    persistence: Option<&dyn CreemWebhookPersistence>,
) -> Result<(), CreemWebhookError> {
    if !validate_webhook_signature(payload, signature, secret) {
        return Err(CreemWebhookError::InvalidSignature);
    }
    let event = parse_webhook_event(payload).map_err(|_| CreemWebhookError::ProcessingFailed)?;
    if !HANDLED_EVENTS.contains(&event.event_type.as_str()) {
        return Err(CreemWebhookError::UnknownEventType);
    }

    persist(&event, persistence).await;
    call_access_callback(&event, callbacks)
        .await
        .map_err(callback_failure)?;
    call_specific_callback(&event, callbacks)
        .await
        .map_err(callback_failure)
}

async fn persist(event: &CreemWebhookEvent, persistence: Option<&dyn CreemWebhookPersistence>) {
    let Some(persistence) = persistence else {
        return;
    };
    match event.event_type.as_str() {
        "checkout.completed" => {
            if let Err(error) = persistence.persist_checkout(&event.object).await {
                tracing::error!(message = %error, "Creem checkout webhook persistence failed");
            }
        }
        event_type if event_type.starts_with("subscription.") => {
            if let Err(error) = persistence
                .persist_subscription(event_type, &event.object)
                .await
            {
                tracing::error!(message = %error, "Creem subscription webhook persistence failed");
            }
            if event_type == "subscription.trialing"
                && let Err(error) = persistence.mark_trial(&event.object).await
            {
                tracing::error!(message = %error, "Creem trial webhook persistence failed");
            }
        }
        _ => {}
    }
}

async fn call_access_callback(
    event: &CreemWebhookEvent,
    callbacks: &CreemWebhookCallbacks,
) -> Result<(), CreemCallbackError> {
    let selected = match event.event_type.as_str() {
        "subscription.active" => callbacks
            .on_grant_access
            .as_deref()
            .map(|callback| (callback, "subscription_active")),
        "subscription.trialing" => callbacks
            .on_grant_access
            .as_deref()
            .map(|callback| (callback, "subscription_trialing")),
        "subscription.paid" => callbacks
            .on_grant_access
            .as_deref()
            .map(|callback| (callback, "subscription_paid")),
        "subscription.expired" => callbacks
            .on_revoke_access
            .as_deref()
            .map(|callback| (callback, "subscription_expired")),
        "subscription.paused" => callbacks
            .on_revoke_access
            .as_deref()
            .map(|callback| (callback, "subscription_paused")),
        _ => None,
    };
    if let Some((callback, reason)) = selected {
        callback.call(access_payload(event, reason)).await?;
    }
    Ok(())
}

async fn call_specific_callback(
    event: &CreemWebhookEvent,
    callbacks: &CreemWebhookCallbacks,
) -> Result<(), CreemCallbackError> {
    let callback: Option<&dyn CreemWebhookCallback> = match event.event_type.as_str() {
        "checkout.completed" => callbacks.on_checkout_completed.as_deref(),
        "refund.created" => callbacks.on_refund_created.as_deref(),
        "dispute.created" => callbacks.on_dispute_created.as_deref(),
        "subscription.active" => callbacks.on_subscription_active.as_deref(),
        "subscription.trialing" => callbacks.on_subscription_trialing.as_deref(),
        "subscription.canceled" => callbacks.on_subscription_canceled.as_deref(),
        "subscription.paid" => callbacks.on_subscription_paid.as_deref(),
        "subscription.expired" => callbacks.on_subscription_expired.as_deref(),
        "subscription.unpaid" => callbacks.on_subscription_unpaid.as_deref(),
        "subscription.update" => callbacks.on_subscription_update.as_deref(),
        "subscription.past_due" => callbacks.on_subscription_past_due.as_deref(),
        "subscription.paused" => callbacks.on_subscription_paused.as_deref(),
        _ => None,
    };
    if let Some(callback) = callback {
        callback.call(specific_payload(event)).await?;
    }
    Ok(())
}

fn specific_payload(event: &CreemWebhookEvent) -> Value {
    let mut payload = Map::from_iter([
        (
            "webhookEventType".into(),
            Value::String(event.event_type.clone()),
        ),
        ("webhookId".into(), Value::String(event.id.clone())),
        (
            "webhookCreatedAt".into(),
            Value::Number(event.created_at.clone()),
        ),
    ]);
    payload.extend(event.object.clone());
    Value::Object(payload)
}

fn access_payload(event: &CreemWebhookEvent, reason: &str) -> Value {
    let mut payload = Map::from_iter([("reason".into(), Value::String(reason.into()))]);
    payload.extend(event.object.clone());
    Value::Object(payload)
}

fn callback_failure(error: CreemCallbackError) -> CreemWebhookError {
    tracing::error!(message = %error, "Creem webhook callback failed");
    CreemWebhookError::ProcessingFailed
}

#[cfg(test)]
mod callback_catalog_tests;

#[cfg(test)]
mod tests {
    use super::super::CreemPersistenceError;
    use super::*;
    use crate::creem::FnCreemWebhookCallback;
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use tokio::sync::Mutex;

    fn signed(event_type: &str, object: Value) -> (String, String) {
        let payload = json!({
            "eventType": event_type,
            "id": "event_1",
            "created_at": 1.5,
            "object": object
        })
        .to_string();
        let signature = super::super::sign_webhook_text(&payload, "whsec_test");
        (payload, signature)
    }

    #[derive(Default)]
    struct RecordingPersistence {
        order: Arc<Mutex<Vec<String>>>,
        fail: AtomicBool,
    }

    #[async_trait]
    impl CreemWebhookPersistence for RecordingPersistence {
        async fn persist_checkout(
            &self,
            _checkout: &Map<String, Value>,
        ) -> Result<(), CreemPersistenceError> {
            self.order.lock().await.push("persist_checkout".into());
            failure(self)
        }

        async fn persist_subscription(
            &self,
            event_type: &str,
            _subscription: &Map<String, Value>,
        ) -> Result<(), CreemPersistenceError> {
            self.order
                .lock()
                .await
                .push(format!("persist:{event_type}"));
            failure(self)
        }

        async fn mark_trial(
            &self,
            _subscription: &Map<String, Value>,
        ) -> Result<(), CreemPersistenceError> {
            self.order.lock().await.push("mark_trial".into());
            failure(self)
        }
    }

    fn failure(persistence: &RecordingPersistence) -> Result<(), CreemPersistenceError> {
        if persistence.fail.load(Ordering::SeqCst) {
            Err(CreemPersistenceError::new("store unavailable"))
        } else {
            Ok(())
        }
    }

    #[tokio::test]
    async fn persistence_then_access_then_specific_are_sequential_with_object_collisions_last() {
        let persistence = RecordingPersistence::default();
        let order = persistence.order.clone();
        let grant_payload = Arc::new(Mutex::new(None));
        let grant_seen = grant_payload.clone();
        let grant_order = order.clone();
        let specific_payload_seen = Arc::new(Mutex::new(None));
        let specific_seen = specific_payload_seen.clone();
        let specific_order = order.clone();
        let callbacks = CreemWebhookCallbacks {
            on_grant_access: Some(Arc::new(FnCreemWebhookCallback::new(move |payload| {
                let grant_seen = grant_seen.clone();
                let order = grant_order.clone();
                async move {
                    order.lock().await.push("grant".into());
                    *grant_seen.lock().await = Some(payload);
                    Ok(())
                }
            }))),
            on_subscription_active: Some(Arc::new(FnCreemWebhookCallback::new(move |payload| {
                let specific_seen = specific_seen.clone();
                let order = specific_order.clone();
                async move {
                    order.lock().await.push("specific".into());
                    *specific_seen.lock().await = Some(payload);
                    Ok(())
                }
            }))),
            ..CreemWebhookCallbacks::default()
        };
        let (payload, signature) = signed(
            "subscription.active",
            json!({
                "object": "refund",
                "reason": "object_reason",
                "webhookEventType": "object_type",
                "webhookId": "object_id",
                "webhookCreatedAt": 999,
                "extra": true
            }),
        );

        process_webhook(
            &payload,
            Some(&signature),
            "whsec_test",
            &callbacks,
            Some(&persistence),
        )
        .await
        .unwrap();

        assert_eq!(
            *order.lock().await,
            ["persist:subscription.active", "grant", "specific"]
        );
        assert_eq!(
            grant_payload.lock().await.as_ref().unwrap()["reason"],
            "object_reason"
        );
        let payload = specific_payload_seen.lock().await;
        let payload = payload.as_ref().unwrap();
        assert_eq!(payload["webhookEventType"], "object_type");
        assert_eq!(payload["webhookId"], "object_id");
        assert_eq!(payload["webhookCreatedAt"], 999);
        assert_eq!(payload["extra"], true);
    }

    #[tokio::test]
    async fn persistence_failures_are_swallowed_but_callback_failure_stops_dispatch() {
        let persistence = RecordingPersistence::default();
        persistence.fail.store(true, Ordering::SeqCst);
        let specific_calls = Arc::new(AtomicUsize::new(0));
        let calls = specific_calls.clone();
        let callbacks = CreemWebhookCallbacks {
            on_grant_access: Some(Arc::new(FnCreemWebhookCallback::new(|_| async {
                Err(CreemCallbackError::new("grant failed"))
            }))),
            on_subscription_trialing: Some(Arc::new(FnCreemWebhookCallback::new(move |_| {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            }))),
            ..CreemWebhookCallbacks::default()
        };
        let (payload, signature) =
            signed("subscription.trialing", json!({"object":"subscription"}));
        assert_eq!(
            process_webhook(
                &payload,
                Some(&signature),
                "whsec_test",
                &callbacks,
                Some(&persistence)
            )
            .await,
            Err(CreemWebhookError::ProcessingFailed)
        );
        assert_eq!(
            *persistence.order.lock().await,
            ["persist:subscription.trialing", "mark_trial"]
        );
        assert_eq!(specific_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unknown_invalid_and_signature_errors_remain_distinct() {
        let callbacks = CreemWebhookCallbacks::default();
        let (unknown, signature) = signed(
            "subscription.scheduled_cancel",
            json!({"object":"subscription"}),
        );
        assert_eq!(
            process_webhook(&unknown, Some(&signature), "whsec_test", &callbacks, None).await,
            Err(CreemWebhookError::UnknownEventType)
        );
        assert_eq!(
            process_webhook(&unknown, None, "whsec_test", &callbacks, None).await,
            Err(CreemWebhookError::InvalidSignature)
        );
        let invalid = "not json";
        let signature = super::super::sign_webhook_text(invalid, "whsec_test");
        assert_eq!(
            process_webhook(invalid, Some(&signature), "whsec_test", &callbacks, None).await,
            Err(CreemWebhookError::ProcessingFailed)
        );
    }

    #[tokio::test]
    async fn repeated_deliveries_repeat_callbacks_without_a_replay_ledger() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let callbacks = CreemWebhookCallbacks {
            on_checkout_completed: Some(Arc::new(FnCreemWebhookCallback::new(move |_| {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            }))),
            ..CreemWebhookCallbacks::default()
        };
        let (payload, signature) = signed("checkout.completed", json!({"object":"checkout"}));
        for _ in 0..2 {
            process_webhook(&payload, Some(&signature), "whsec_test", &callbacks, None)
                .await
                .unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
