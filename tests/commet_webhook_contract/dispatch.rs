use super::support::{CallbackLog, callbacks, fixture, signed_request};
use axum::http::StatusCode;
use lucid_auth::{CommetWebhookCallbacks, FnCommetWebhookCallback, SharedCommetWebhookPayload};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;

fn log() -> CallbackLog {
    Arc::new(Mutex::new(Vec::new()))
}

#[tokio::test]
async fn truthy_scalars_arrays_and_unknown_events_reach_only_the_catch_all() {
    let log = log();
    let fixture = fixture(callbacks(log.clone(), false));
    let payloads = [
        json!(true),
        json!(1),
        json!("truthy string"),
        json!(["truthy array"]),
        json!({"event": "unknown.event", "id": "evt_unknown"}),
    ];

    for payload in &payloads {
        let body = payload.to_string();
        let response = fixture.send(signed_request(&body, None)).await;
        assert_eq!(response.status, StatusCode::OK, "payload {payload}");
        assert_eq!(
            serde_json::from_str::<Value>(&response.body).unwrap(),
            json!({"received": true}),
        );
    }

    assert_eq!(
        *log.lock().await,
        payloads
            .into_iter()
            .map(|payload| ("catch-all", payload))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn named_callback_runs_before_the_catch_all() {
    let log = log();
    let fixture = fixture(callbacks(log.clone(), false));
    let payload = json!({
        "data": {"id": "sub_1"},
        "event": "subscription.created",
        "id": "evt_1",
    });
    let response = fixture
        .send(signed_request(&payload.to_string(), None))
        .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        *log.lock().await,
        vec![
            ("specific", payload.clone()),
            ("catch-all", payload.clone()),
        ]
    );
}

#[tokio::test]
async fn catch_all_observes_named_callback_mutations_on_the_shared_payload() {
    let observed = Arc::new(Mutex::new(None));
    let named = FnCommetWebhookCallback::new(|payload: SharedCommetWebhookPayload| async move {
        payload.lock().await["namedMutation"] = Value::Bool(true);
        Ok(())
    });
    let catch_all = FnCommetWebhookCallback::new({
        let observed = observed.clone();
        move |payload: SharedCommetWebhookPayload| {
            let observed = observed.clone();
            async move {
                *observed.lock().await = Some(payload.lock().await.clone());
                Ok(())
            }
        }
    });
    let callbacks = CommetWebhookCallbacks {
        on_payload: Some(Arc::new(catch_all)),
        on_subscription_created: Some(Arc::new(named)),
        ..CommetWebhookCallbacks::default()
    };
    let fixture = fixture(callbacks);
    let payload = json!({"event": "subscription.created", "id": "evt_shared"});

    let response = fixture
        .send(signed_request(&payload.to_string(), None))
        .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        *observed.lock().await,
        Some(json!({
            "event": "subscription.created",
            "id": "evt_shared",
            "namedMutation": true,
        }))
    );
}

#[tokio::test]
async fn named_callback_failure_is_generic_and_skips_the_catch_all() {
    let log = log();
    let fixture = fixture(callbacks(log.clone(), true));
    let payload = json!({"event": "subscription.created", "id": "evt_1"});
    let response = fixture
        .send(signed_request(&payload.to_string(), None))
        .await;

    assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response.body, r#"{"message":"Webhook handler error"}"#);
    assert_eq!(*log.lock().await, vec![("specific", payload)]);
}

#[tokio::test]
async fn repeated_deliveries_are_dispatched_without_deduplication() {
    let log = log();
    let fixture = fixture(callbacks(log.clone(), false));
    let payload = json!({"event": "subscription.created", "id": "evt_repeat"});
    let body = payload.to_string();

    for _ in 0..2 {
        let response = fixture.send(signed_request(&body, None)).await;
        assert_eq!(response.status, StatusCode::OK);
    }
    assert_eq!(
        *log.lock().await,
        vec![
            ("specific", payload.clone()),
            ("catch-all", payload.clone()),
            ("specific", payload.clone()),
            ("catch-all", payload),
        ]
    );
}

#[tokio::test]
async fn no_callbacks_still_acknowledges_a_valid_delivery() {
    let fixture = fixture(CommetWebhookCallbacks::default());
    let body = json!({"event": "unknown.event"}).to_string();
    let response = fixture.send(signed_request(&body, None)).await;
    assert_eq!(response.status, StatusCode::OK);
}
