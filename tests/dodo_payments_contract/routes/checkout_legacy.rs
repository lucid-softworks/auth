use super::super::support::{DodoCall, fixture, post};
use super::checkout;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn returns_redirect_and_translates_payment_payload() {
    let fixture = fixture(vec![checkout(false)], false, false).await;
    let billing = json!({
        "city": "London",
        "country": "GB",
        "state": "London",
        "street": "1 Contract Way",
        "zipcode": "N1 1AA"
    });
    let (status, body) = post(
        &fixture,
        "/api/auth/dodopayments/checkout",
        json!({
            "billing": billing,
            "customer": {"email": "legacy@example.test", "name": "Legacy"},
            "slug": "pro",
            "referenceId": "ref_legacy",
            "metadata": {"order": "contract"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"url": "https://checkout.dodo.test/payment", "redirect": true})
    );

    let calls = fixture.client.calls().await;
    assert_eq!(calls[0], DodoCall::RetrieveProduct("prod_pro".into()));
    let DodoCall::Payment(payment) = &calls[1] else {
        panic!("expected payment call, got {:?}", calls[1]);
    };
    assert_eq!(payment["billing"], billing);
    assert_eq!(payment["customer"]["email"], "legacy@example.test");
    assert_eq!(
        payment["product_cart"],
        json!([{"product_id": "prod_pro", "quantity": 1}])
    );
    assert_eq!(
        payment["metadata"],
        json!({"referenceId": "ref_legacy", "order": "contract"})
    );
    assert_eq!(payment["payment_link"], true);
    assert_eq!(
        payment["return_url"],
        "http://app.example.test/checkout-complete"
    );
}
