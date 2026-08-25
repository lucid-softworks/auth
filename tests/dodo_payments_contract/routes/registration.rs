use super::super::support::{fixture, get, post};
use super::checkout;
use axum::http::StatusCode;
use lucid_auth::DodoPaymentsFeature;
use serde_json::json;

#[tokio::test]
async fn only_selected_feature_groups_register_routes() {
    let empty = fixture(Vec::new(), false, false).await;
    for path in [
        "/api/auth/dodopayments/checkout",
        "/api/auth/dodopayments/customer/portal",
        "/api/auth/dodopayments/usage/ingest",
        "/api/auth/dodopayments/webhooks",
    ] {
        let (status, _) = post(&empty, path, json!({})).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }

    let selected = fixture(
        vec![checkout(false), DodoPaymentsFeature::Usage],
        false,
        false,
    )
    .await;
    let (status, _) = post(
        &selected,
        "/api/auth/dodopayments/checkout-session",
        json!({}),
    )
    .await;
    assert_ne!(status, StatusCode::NOT_FOUND);
    let (status, _) = post(&selected, "/api/auth/dodopayments/usage/ingest", json!({})).await;
    assert_ne!(status, StatusCode::NOT_FOUND);
    let (status, _) = get(&selected, "/api/auth/dodopayments/customer/portal").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
