use super::super::support::{ChargebeeCall, fixture, get, post};
use axum::http::StatusCode;
use lucid_auth::{
    ChargebeeItemType, ChargebeeProviderSubscription, ChargebeeProviderSubscriptionItem,
    ChargebeeStore, ChargebeeSubscription, ChargebeeSubscriptionItem, ChargebeeSubscriptionStatus,
};
use serde_json::json;
use std::collections::BTreeMap;

#[tokio::test]
async fn portal_uses_the_user_customer_field_without_needing_a_subscription() {
    let fixture = fixture(true, |_| {}).await;
    fixture
        .store
        .set_user_customer_id(fixture.user_id.unwrap(), Some("customer_portal".into()))
        .await
        .unwrap();
    let (status, body) = post(
        &fixture,
        "/api/auth/subscription/portal",
        json!({"returnUrl": "/billing", "disableRedirect": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({
            "url": "https://chargebee.example.test/portal/contract",
            "redirect": false
        })
    );
    let calls = fixture.client.calls().await;
    let request = calls.iter().find_map(|call| match call {
        ChargebeeCall::Portal(request) => Some(request),
        _ => None,
    });
    assert_eq!(request.unwrap()["customer"]["id"], "customer_portal");
    assert_eq!(
        request.unwrap()["redirect_url"],
        "http://localhost/api/auth/billing"
    );
}

#[tokio::test]
async fn list_is_local_only_filters_statuses_and_prefers_the_first_plan_item() {
    let fixture = fixture(true, |_| {}).await;
    let reference = fixture.user_id.unwrap().to_string();
    let active =
        create_subscription(&fixture, &reference, ChargebeeSubscriptionStatus::Active).await;
    create_subscription(&fixture, &reference, ChargebeeSubscriptionStatus::Paused).await;
    fixture
        .store
        .create_subscription_item(ChargebeeSubscriptionItem::new(
            active.id,
            "price_addon",
            ChargebeeItemType::Addon,
            1.0,
        ))
        .await
        .unwrap();
    fixture
        .store
        .create_subscription_item(ChargebeeSubscriptionItem::new(
            active.id,
            "price_pro",
            ChargebeeItemType::Plan,
            1.0,
        ))
        .await
        .unwrap();

    let (status, body) = get(&fixture, "/api/auth/subscription/list").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["status"], "active");
    assert_eq!(body[0]["itemPriceId"], "price_pro");
    assert_eq!(body[0]["limits"], json!({"projects": 10}));
    assert!(fixture.client.calls().await.is_empty());
}

#[tokio::test]
async fn cancel_opens_the_portal_and_embeds_the_exact_callback_url() {
    let fixture = fixture(true, |_| {}).await;
    let reference = fixture.user_id.unwrap().to_string();
    let mut local = ChargebeeSubscription::future(&reference);
    local.status = ChargebeeSubscriptionStatus::Active;
    local.chargebee_customer_id = Some("customer_cancel".into());
    local.chargebee_subscription_id = Some("subscription_cancel".into());
    let local = fixture.store.create_subscription(local).await.unwrap();
    fixture
        .client
        .set_provider_subscriptions(vec![provider_subscription(
            "subscription_cancel",
            "customer_cancel",
            "active",
        )])
        .await;

    let (status, body) = post(
        &fixture,
        "/api/auth/subscription/cancel",
        json!({"returnUrl": "/pricing?cancelled=true", "disableRedirect": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let calls = fixture.client.calls().await;
    let request = calls.iter().find_map(|call| match call {
        ChargebeeCall::Portal(request) => Some(request),
        _ => None,
    });
    assert_eq!(request.unwrap()["customer"]["id"], "customer_cancel");
    assert_eq!(
        request.unwrap()["redirect_url"],
        format!(
            "http://localhost/api/auth/subscription/cancel/callback?callbackURL=%2Fpricing%3Fcancelled%3Dtrue&subscriptionId={}",
            local.id
        )
    );
}

async fn create_subscription(
    fixture: &super::super::support::Fixture,
    reference: &str,
    status: ChargebeeSubscriptionStatus,
) -> ChargebeeSubscription {
    let mut subscription = ChargebeeSubscription::future(reference);
    subscription.status = status;
    fixture
        .store
        .create_subscription(subscription)
        .await
        .unwrap()
}

fn provider_subscription(
    id: &str,
    customer_id: &str,
    status: &str,
) -> ChargebeeProviderSubscription {
    ChargebeeProviderSubscription {
        id: id.into(),
        customer_id: customer_id.into(),
        status: status.into(),
        current_term_start: None,
        current_term_end: None,
        trial_start: None,
        trial_end: None,
        cancelled_at: None,
        subscription_items: vec![ChargebeeProviderSubscriptionItem {
            item_price_id: "price_pro".into(),
            item_type: Some("plan".into()),
            quantity: Some(1.0),
            unit_price: None,
            amount: None,
            extra: BTreeMap::new(),
        }],
        metadata: None,
        extra: BTreeMap::new(),
    }
}
