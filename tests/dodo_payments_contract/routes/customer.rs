use super::super::support::{DodoCall, fixture, get};
use axum::http::StatusCode;
use lucid_auth::{DodoPaymentStatus, DodoPaymentsFeature, DodoSubscriptionStatus};
use serde_json::json;

#[tokio::test]
async fn portal_and_lists_require_verified_auth_and_translate_queries() {
    let anonymous = fixture(vec![DodoPaymentsFeature::Portal], false, false).await;
    let (status, body) = get(&anonymous, "/api/auth/dodopayments/customer/portal").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"message": "Unauthorized"}));

    let unverified = fixture(vec![DodoPaymentsFeature::Portal], true, false).await;
    let (status, body) = get(&unverified, "/api/auth/dodopayments/customer/portal").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"message": "User email not verified"}));

    let fixture = fixture(vec![DodoPaymentsFeature::Portal], true, true).await;
    let (status, body) = get(&fixture, "/api/auth/dodopayments/customer/portal").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"url": "https://portal.dodo.test/customer", "redirect": true})
    );

    let (status, body) = get(
        &fixture,
        "/api/auth/dodopayments/customer/subscriptions/list?page=3&limit=7&status=on_hold",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"items": [{"subscription_id": "sub_contract"}]})
    );

    let (status, body) = get(
        &fixture,
        "/api/auth/dodopayments/customer/payments/list?page=0&limit=11&status=requires_customer_action",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"items": [{"payment_id": "pay_contract"}]}));

    let calls = fixture.client.calls().await;
    assert_eq!(calls[0], DodoCall::Portal("cus_contract".into()));
    let DodoCall::ListSubscriptions(request) = &calls[1] else {
        panic!("expected subscription-list call, got {:?}", calls[1]);
    };
    assert_eq!(request.customer_id, "cus_contract");
    assert_eq!(request.page_number, Some(2.0));
    assert_eq!(request.page_size, Some(7.0));
    assert_eq!(request.status, Some(DodoSubscriptionStatus::OnHold));
    let DodoCall::ListPayments(request) = &calls[2] else {
        panic!("expected payment-list call, got {:?}", calls[2]);
    };
    assert_eq!(request.customer_id, "cus_contract");
    assert_eq!(request.page_number, None);
    assert_eq!(request.page_size, Some(11.0));
    assert_eq!(
        request.status,
        Some(DodoPaymentStatus::RequiresCustomerAction)
    );
}
