use super::*;
use crate::commet::{
    FnCommetWebhookCallback, SharedCommetWebhookCallback, SharedCommetWebhookPayload,
};
use std::sync::Arc;
use tokio::sync::Mutex;

const SECRET: &str = "commet webhook secret";

fn callback(
    name: &'static str,
    calls: Arc<Mutex<Vec<String>>>,
    fail: bool,
) -> SharedCommetWebhookCallback {
    Arc::new(FnCommetWebhookCallback::new(
        move |payload: SharedCommetWebhookPayload| {
            let calls = calls.clone();
            async move {
                let payload = payload.lock().await.clone();
                calls.lock().await.push(format!("{name}:{payload}"));
                if fail {
                    Err(CommetWebhookCallbackError::new("intentional failure"))
                } else {
                    Ok(())
                }
            }
        },
    ))
}

#[tokio::test]
async fn named_callback_mutations_are_shared_with_catch_all_and_returned() {
    let observed = Arc::new(Mutex::new(None));
    let named = Arc::new(FnCommetWebhookCallback::new(
        |payload: SharedCommetWebhookPayload| async move {
            payload.lock().await["namedMutation"] = Value::Bool(true);
            Ok(())
        },
    ));
    let catch_all = Arc::new(FnCommetWebhookCallback::new({
        let observed = observed.clone();
        move |payload: SharedCommetWebhookPayload| {
            let observed = observed.clone();
            async move {
                let mut payload = payload.lock().await;
                *observed.lock().await = Some(payload.clone());
                payload["catchAllMutation"] = Value::Bool(true);
                Ok(())
            }
        }
    }));
    let callbacks = callbacks_for("payment.received", named, catch_all);
    let body = r#"{"event":"payment.received"}"#;
    let signature = super::super::sign_commet_webhook(body, SECRET);

    let payload = process_commet_webhook(body, Some(&signature), SECRET, &callbacks)
        .await
        .unwrap();

    assert_eq!(
        *observed.lock().await,
        Some(serde_json::json!({
            "event": "payment.received",
            "namedMutation": true,
        }))
    );
    assert_eq!(payload["namedMutation"], true);
    assert_eq!(payload["catchAllMutation"], true);
}

fn callbacks_for(
    event: &str,
    named: SharedCommetWebhookCallback,
    catch_all: SharedCommetWebhookCallback,
) -> CommetWebhookCallbacks {
    let mut callbacks = CommetWebhookCallbacks {
        on_payload: Some(catch_all),
        ..CommetWebhookCallbacks::default()
    };
    match event {
        "subscription.created" => callbacks.on_subscription_created = Some(named),
        "subscription.activated" => callbacks.on_subscription_activated = Some(named),
        "subscription.canceled" => callbacks.on_subscription_canceled = Some(named),
        "subscription.updated" => callbacks.on_subscription_updated = Some(named),
        "subscription.plan_changed" => callbacks.on_subscription_plan_changed = Some(named),
        "payment.received" => callbacks.on_payment_received = Some(named),
        "payment.failed" => callbacks.on_payment_failed = Some(named),
        "invoice.created" => callbacks.on_invoice_created = Some(named),
        _ => panic!("test event is not mapped"),
    }
    callbacks
}

#[tokio::test]
async fn all_eight_events_dispatch_specific_then_catch_all() {
    for event in [
        "subscription.created",
        "subscription.activated",
        "subscription.canceled",
        "subscription.updated",
        "subscription.plan_changed",
        "payment.received",
        "payment.failed",
        "invoice.created",
    ] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let callbacks = callbacks_for(
            event,
            callback("specific", calls.clone(), false),
            callback("all", calls.clone(), false),
        );
        let body = serde_json::json!({"event": event, "data": {"id": "evt_1"}}).to_string();
        let signature = super::super::sign_commet_webhook(&body, SECRET);

        let payload = process_commet_webhook(&body, Some(&signature), SECRET, &callbacks)
            .await
            .unwrap();

        assert_eq!(payload["event"], event);
        assert_eq!(
            calls
                .lock()
                .await
                .iter()
                .map(|entry| entry.split(':').next().unwrap())
                .collect::<Vec<_>>(),
            ["specific", "all"]
        );
    }
}

#[tokio::test]
async fn unknown_and_truthy_non_object_payloads_reach_only_catch_all() {
    for body in [
        r#"{"event":"future.event","data":{}}"#,
        r#"{"data":{}}"#,
        r#"[]"#,
        r#""truthy""#,
        r#"1"#,
        r#"true"#,
    ] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let callbacks = CommetWebhookCallbacks {
            on_payload: Some(callback("all", calls.clone(), false)),
            on_payment_received: Some(callback("specific", calls.clone(), false)),
            ..CommetWebhookCallbacks::default()
        };
        let signature = super::super::sign_commet_webhook(body, SECRET);

        process_commet_webhook(body, Some(&signature), SECRET, &callbacks)
            .await
            .unwrap();

        assert_eq!(calls.lock().await.len(), 1);
        assert!(calls.lock().await[0].starts_with("all:"));
    }
}

#[test]
fn validly_signed_json_falsy_payloads_are_invalid_signatures() {
    for body in ["null", "false", "0", "-0", "0.0", r#"""#] {
        let signature = super::super::sign_commet_webhook(body, SECRET);
        assert!(matches!(
            parse_verified_payload(body, Some(&signature), SECRET),
            Err(CommetWebhookError::InvalidSignature)
        ));
    }
}

#[tokio::test]
async fn specific_failure_skips_catch_all() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let callbacks = callbacks_for(
        "payment.failed",
        callback("specific", calls.clone(), true),
        callback("all", calls.clone(), false),
    );
    let body = r#"{"event":"payment.failed"}"#;
    let signature = super::super::sign_commet_webhook(body, SECRET);

    let error = process_commet_webhook(body, Some(&signature), SECRET, &callbacks)
        .await
        .unwrap_err();

    assert_eq!(error.to_string(), "Webhook handler error");
    assert_eq!(calls.lock().await.len(), 1);
}

#[tokio::test]
async fn catch_all_failure_is_reported_after_specific_success() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let callbacks = callbacks_for(
        "payment.received",
        callback("specific", calls.clone(), false),
        callback("all", calls.clone(), true),
    );
    let body = r#"{"event":"payment.received"}"#;
    let signature = super::super::sign_commet_webhook(body, SECRET);

    let error = process_commet_webhook(body, Some(&signature), SECRET, &callbacks)
        .await
        .unwrap_err();

    assert_eq!(error.to_string(), "Webhook handler error");
    assert_eq!(calls.lock().await.len(), 2);
}

#[tokio::test]
async fn repeated_delivery_runs_callbacks_each_time() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let callbacks = callbacks_for(
        "invoice.created",
        callback("specific", calls.clone(), false),
        callback("all", calls.clone(), false),
    );
    let body = r#"{"event":"invoice.created","id":"event_1"}"#;
    let signature = super::super::sign_commet_webhook(body, SECRET);

    for _ in 0..2 {
        process_commet_webhook(body, Some(&signature), SECRET, &callbacks)
            .await
            .unwrap();
    }

    assert_eq!(calls.lock().await.len(), 4);
}

#[test]
fn malformed_json_and_mismatched_signatures_share_the_sdk_failure_boundary() {
    let malformed = "{";
    let signature = super::super::sign_commet_webhook(malformed, SECRET);
    assert!(matches!(
        parse_verified_payload(malformed, Some(&signature), SECRET),
        Err(CommetWebhookError::InvalidSignature)
    ));
    assert!(matches!(
        parse_verified_payload("{}", Some(&signature), SECRET),
        Err(CommetWebhookError::InvalidSignature)
    ));
}
