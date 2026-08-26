use super::super::support::{ChargebeeCall, fixture, post};
use axum::http::StatusCode;
use lucid_auth::{
    ChargebeeProviderSubscription, ChargebeeProviderSubscriptionItem, ChargebeeStore,
    ChargebeeSubscription, ChargebeeSubscriptionStatus,
};
use serde_json::json;
use std::collections::BTreeMap;

#[tokio::test]
async fn update_selects_the_matching_active_provider_subscription() {
    let fixture = fixture(true, |_| {}).await;
    let user_id = fixture.user_id.unwrap();
    fixture
        .store
        .set_user_customer_id(user_id, Some("customer_update".into()))
        .await
        .unwrap();
    let mut local = ChargebeeSubscription::future(user_id.to_string());
    local.status = ChargebeeSubscriptionStatus::Active;
    local.chargebee_customer_id = Some("customer_update".into());
    local.chargebee_subscription_id = Some("subscription_update".into());
    local.seats = Some(1.0);
    fixture.store.create_subscription(local).await.unwrap();
    fixture
        .client
        .set_provider_subscriptions(vec![provider_subscription()])
        .await;

    let (status, body) = post(
        &fixture,
        "/api/auth/subscription/update",
        json!({
            "itemPriceId": "price_pro",
            "successUrl": "/complete",
            "cancelUrl": "/plans",
            "seats": 5,
            "disableRedirect": true
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["id"], "hosted_page_update");
    let calls = fixture.client.calls().await;
    let request = calls.iter().find_map(|call| match call {
        ChargebeeCall::CheckoutExisting(request) => Some(request),
        _ => None,
    });
    assert_eq!(
        request.unwrap()["subscription"]["id"],
        "subscription_update"
    );
    assert_eq!(request.unwrap()["subscription_items"][0]["quantity"], 5.0);
}

fn provider_subscription() -> ChargebeeProviderSubscription {
    ChargebeeProviderSubscription {
        id: "subscription_update".into(),
        customer_id: "customer_update".into(),
        status: "active".into(),
        current_term_start: None,
        current_term_end: None,
        trial_start: None,
        trial_end: None,
        cancelled_at: None,
        subscription_items: vec![ChargebeeProviderSubscriptionItem {
            item_price_id: "price_old".into(),
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
