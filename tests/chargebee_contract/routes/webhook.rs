use super::super::support::{fixture, post, raw_post};
use async_trait::async_trait;
use axum::http::StatusCode;
use lucid_auth::{
    ChargebeeCallbackError, ChargebeeStore, ChargebeeSubscriptionStatus, ChargebeeWebhookEvent,
    ChargebeeWebhookEventBus,
};
use serde_json::json;
use std::sync::Arc;

struct FailingBus;

#[async_trait]
impl ChargebeeWebhookEventBus for FailingBus {
    async fn publish(&self, _event: ChargebeeWebhookEvent) -> Result<(), ChargebeeCallbackError> {
        Err(ChargebeeCallbackError::new("queue implementation detail"))
    }
}

#[tokio::test]
async fn configured_basic_auth_rejects_invalid_credentials_but_payload_errors_acknowledge() {
    let secured = fixture(false, |options| {
        options.webhook_username = Some("user".into());
        options.webhook_password = Some("pass".into());
    })
    .await;
    let event = json!({"event_type": "unhandled_event", "id": "evt", "content": {}}).to_string();
    let (status, _) = raw_post(
        &secured,
        "/api/auth/chargebee/webhook",
        &event,
        Some("Basic invalid"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = raw_post(
        &secured,
        "/api/auth/chargebee/webhook",
        "not-json",
        Some("Basic dXNlcjpwYXNz"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"received": true}));
}

#[tokio::test]
async fn webhook_bus_is_awaited_and_failure_uses_the_public_message() {
    let fixture = fixture(false, |options| {
        options.webhook_event_bus = Some(Arc::new(FailingBus));
    })
    .await;
    let event =
        json!({"event_type": "subscription_created", "id": "evt", "content": {}}).to_string();
    let (status, body) = raw_post(&fixture, "/api/auth/chargebee/webhook", &event, None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["message"], "Failed to queue webhook event");
}

#[tokio::test]
async fn activated_webhook_promotes_pending_without_creating_item_rows() {
    let fixture = fixture(true, |_| {}).await;
    let (status, _) = post(
        &fixture,
        "/api/auth/subscription/create",
        json!({
            "itemPriceId": "price_pro",
            "successUrl": "/success",
            "cancelUrl": "/cancel",
            "disableRedirect": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let reference = fixture.user_id.unwrap().to_string();
    let pending = fixture
        .store
        .list_subscriptions_by_reference(&reference)
        .await
        .unwrap()
        .remove(0);
    let event = json!({
        "event_type": "subscription_activated",
        "id": "event_activated",
        "content": {
            "customer": {
                "id": "customer_contract",
                "meta_data": {"pendingSubscriptionId": pending.id.to_string()}
            },
            "subscription": {
                "id": "subscription_provider",
                "customer_id": "customer_contract",
                "status": "active",
                "current_term_start": 1700000000,
                "current_term_end": 1702592000,
                "subscription_items": [{
                    "item_price_id": "price_pro",
                    "item_type": "plan",
                    "quantity": 4,
                    "unit_price": 2500,
                    "amount": 10000
                }]
            }
        }
    })
    .to_string();
    let (status, body) = raw_post(&fixture, "/api/auth/chargebee/webhook", &event, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let updated = fixture
        .store
        .find_subscription(pending.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.status, ChargebeeSubscriptionStatus::Active);
    assert_eq!(
        updated.chargebee_subscription_id.as_deref(),
        Some("subscription_provider")
    );
    assert_eq!(updated.seats, Some(4.0));
    let items = fixture
        .store
        .list_subscription_items(pending.id)
        .await
        .unwrap();
    assert!(items.is_empty());
}
