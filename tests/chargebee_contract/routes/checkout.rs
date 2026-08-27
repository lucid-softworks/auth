use super::super::support::{ChargebeeCall, fixture, post};
use axum::http::StatusCode;
use lucid_auth::{ChargebeeProviderError, ChargebeeStore, ChargebeeSubscriptionStatus};
use serde_json::json;

fn create_body(seats: f64) -> serde_json::Value {
    json!({
        "itemPriceId": ["price_pro", "price_addon"],
        "successUrl": "/billing/success?from=checkout",
        "cancelUrl": "/pricing",
        "seats": seats,
        "metadata": {"campaign": "contract"},
        "disableRedirect": true
    })
}

#[tokio::test]
async fn create_persists_future_before_provider_and_builds_exact_hosted_page_request() {
    let fixture = fixture(true, |_| {}).await;
    let (status, body) = post(&fixture, "/api/auth/subscription/create", create_body(3.0)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({
            "id": "hosted_page_contract",
            "redirect": false,
            "url": "https://chargebee.example.test/checkout/contract"
        })
    );

    let user_id = fixture.user_id.as_deref().unwrap();
    let subscriptions = fixture
        .store
        .list_subscriptions_by_reference(user_id)
        .await
        .unwrap();
    assert_eq!(subscriptions.len(), 1);
    assert_eq!(subscriptions[0].status, ChargebeeSubscriptionStatus::Future);
    assert_eq!(subscriptions[0].seats, Some(3.0));

    let calls = fixture.client.calls().await;
    let request = calls
        .iter()
        .find_map(|call| match call {
            ChargebeeCall::CheckoutNew(request) => Some(request),
            _ => None,
        })
        .expect("checkout request");
    assert_eq!(request["customer"]["id"], "customer_contract");
    assert_eq!(
        request["subscription_items"][0],
        json!({
            "item_price_id": "price_pro",
            "quantity": 3.0
        })
    );
    assert_eq!(
        request["subscription_items"][1]["item_price_id"],
        "price_addon"
    );
    assert_eq!(request["cancel_url"], "http://localhost/api/auth/pricing");
    let redirect = request["redirect_url"].as_str().unwrap();
    assert!(redirect.starts_with(
        "http://localhost/api/auth/subscription/success?callbackURL=%2Fbilling%2Fsuccess%3Ffrom%3Dcheckout&subscriptionId="
    ));
}

#[tokio::test]
async fn failed_checkout_leaves_and_reuses_the_first_future_row_with_new_seats() {
    let fixture = fixture(true, |_| {}).await;
    fixture
        .client
        .fail_checkout(ChargebeeProviderError::new("checkout unavailable"))
        .await;
    let (status, body) = post(&fixture, "/api/auth/subscription/create", create_body(2.0)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["message"], "checkout unavailable");

    let reference = fixture.user_id.as_deref().unwrap().to_owned();
    let before = fixture
        .store
        .list_subscriptions_by_reference(&reference)
        .await
        .unwrap();
    assert_eq!(before.len(), 1);
    let id = before[0].id;

    let (status, _) = post(&fixture, "/api/auth/subscription/create", create_body(9.0)).await;
    assert_eq!(status, StatusCode::OK);
    let after = fixture
        .store
        .list_subscriptions_by_reference(&reference)
        .await
        .unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].id, id);
    assert_eq!(after[0].seats, Some(9.0));
}
