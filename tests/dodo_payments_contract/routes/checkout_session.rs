use super::super::support::{DodoCall, fixture, post};
use super::checkout;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn returns_redirect_and_translates_provider_payload() {
    let fixture = fixture(vec![checkout(false)], false, false).await;
    let (status, body) = post(
        &fixture,
        "/api/auth/dodopayments/checkout-session",
        json!({
            "slug": "pro",
            "referenceId": "synthetic",
            "customer": {"email": "buyer@example.test", "name": "Buyer"},
            "metadata": {"referenceId": "caller", "tier": "gold"},
            "return_url": "https://caller.example.test/ignored",
            "unknown": "removed"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"url": "https://checkout.dodo.test/session", "redirect": true})
    );

    let calls = fixture.client.calls().await;
    let DodoCall::CheckoutSession(session) = &calls[0] else {
        panic!("expected checkout-session call, got {:?}", calls[0]);
    };
    assert_eq!(
        session,
        &json!({
            "product_cart": [{"product_id": "prod_pro", "quantity": 1}],
            "customer": {"email": "buyer@example.test", "name": "Buyer"},
            "metadata": {"referenceId": "caller", "tier": "gold"},
            "return_url": "http://app.example.test/checkout-complete"
        })
    );
}
