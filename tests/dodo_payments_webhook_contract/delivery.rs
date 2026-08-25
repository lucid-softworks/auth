use super::support::{app, known_body, now, signed_post, webhook_secret};
use axum::http::StatusCode;
use lucid_auth::{
    DodoWebhookCallbackError, DodoWebhookCallbacks, DodoWebhookEventType, FnDodoWebhookCallback,
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Mutex;

#[tokio::test]
async fn known_signed_delivery_runs_generic_then_named_callbacks() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let generic_calls = calls.clone();
    let named_calls = calls.clone();
    let mut callbacks = DodoWebhookCallbacks::default();
    callbacks.on_payload = Some(Arc::new(FnDodoWebhookCallback::new(move |_event| {
        let calls = generic_calls.clone();
        async move {
            calls.lock().await.push("generic");
            Ok(())
        }
    })));
    let callbacks = callbacks.on(
        DodoWebhookEventType::DunningStarted,
        Arc::new(FnDodoWebhookCallback::new(move |_event| {
            let calls = named_calls.clone();
            async move {
                calls.lock().await.push("named");
                Ok(())
            }
        })),
    );
    let secret = webhook_secret();
    let response = signed_post(
        &app(&secret, callbacks),
        "evt_order",
        now(),
        &known_body(),
        &secret,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json(), json!({"received":true}));
    assert_eq!(*calls.lock().await, ["generic", "named"]);
}

#[tokio::test]
async fn generic_callback_failure_prevents_the_named_callback() {
    let named_calls = Arc::new(AtomicUsize::new(0));
    let named_probe = named_calls.clone();
    let mut callbacks = DodoWebhookCallbacks::default();
    callbacks.on_payload = Some(Arc::new(FnDodoWebhookCallback::new(|_event| async {
        Err(DodoWebhookCallbackError::new("callback exploded"))
    })));
    let callbacks = callbacks.on(
        DodoWebhookEventType::DunningStarted,
        Arc::new(FnDodoWebhookCallback::new(move |_event| {
            let calls = named_probe.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })),
    );
    let secret = webhook_secret();
    let response = signed_post(
        &app(&secret, callbacks),
        "evt_failure",
        now(),
        &known_body(),
        &secret,
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json(),
        json!({"message":"Webhook error: See server logs for more information."})
    );
    assert_eq!(named_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn repeated_signed_delivery_invokes_callbacks_again() {
    let calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = calls.clone();
    let mut callbacks = DodoWebhookCallbacks::default();
    callbacks.on_payload = Some(Arc::new(FnDodoWebhookCallback::new(move |_event| {
        let calls = callback_calls.clone();
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    })));
    let secret = webhook_secret();
    let app = app(&secret, callbacks);
    let body = known_body();
    let timestamp = now();
    for _ in 0..2 {
        let response = signed_post(&app, "evt_repeated", timestamp, &body, &secret).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.json(), json!({"received":true}));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
