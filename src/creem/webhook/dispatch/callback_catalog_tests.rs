use super::*;
use crate::creem::FnCreemWebhookCallback;
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test]
async fn exact_twelve_specific_and_five_access_mappings_are_dispatched() {
    let specific_count = Arc::new(AtomicUsize::new(0));
    let specific_seen = specific_count.clone();
    let specific: Arc<dyn CreemWebhookCallback> =
        Arc::new(FnCreemWebhookCallback::new(move |_| {
            let seen = specific_seen.clone();
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }));
    let grant_count = Arc::new(AtomicUsize::new(0));
    let grant_seen = grant_count.clone();
    let grant: Arc<dyn CreemWebhookCallback> = Arc::new(FnCreemWebhookCallback::new(move |_| {
        let seen = grant_seen.clone();
        async move {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }));
    let revoke_count = Arc::new(AtomicUsize::new(0));
    let revoke_seen = revoke_count.clone();
    let revoke: Arc<dyn CreemWebhookCallback> = Arc::new(FnCreemWebhookCallback::new(move |_| {
        let seen = revoke_seen.clone();
        async move {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }));
    let callbacks = CreemWebhookCallbacks {
        on_checkout_completed: Some(specific.clone()),
        on_refund_created: Some(specific.clone()),
        on_dispute_created: Some(specific.clone()),
        on_subscription_active: Some(specific.clone()),
        on_subscription_trialing: Some(specific.clone()),
        on_subscription_canceled: Some(specific.clone()),
        on_subscription_paid: Some(specific.clone()),
        on_subscription_expired: Some(specific.clone()),
        on_subscription_unpaid: Some(specific.clone()),
        on_subscription_update: Some(specific.clone()),
        on_subscription_past_due: Some(specific.clone()),
        on_subscription_paused: Some(specific),
        on_grant_access: Some(grant),
        on_revoke_access: Some(revoke),
    };

    for event_type in HANDLED_EVENTS {
        let payload = json!({
            "eventType": event_type,
            "id": format!("event_{event_type}"),
            "created_at": 1,
            "object": {"object":"customer"}
        })
        .to_string();
        let signature = super::super::sign_webhook_text(&payload, "whsec_test");
        process_webhook(&payload, Some(&signature), "whsec_test", &callbacks, None)
            .await
            .unwrap();
    }

    assert_eq!(specific_count.load(Ordering::SeqCst), 12);
    assert_eq!(grant_count.load(Ordering::SeqCst), 3);
    assert_eq!(revoke_count.load(Ordering::SeqCst), 2);
}
