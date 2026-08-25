use super::super::support::{fixture, post};
use super::checkout;
use async_trait::async_trait;
use axum::http::StatusCode;
use lucid_auth::{
    DodoCheckoutOptions, DodoPaymentsCallbackError, DodoPaymentsFeature, DodoProducts,
    DodoProductsProvider,
};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn validation_and_guards_follow_upstream_precedence_and_error_shapes() {
    let restricted = fixture(vec![checkout(true)], false, false).await;
    let (status, body) = post(&restricted, "/api/auth/dodopayments/checkout", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({
            "code": "VALIDATION_ERROR",
            "message": "[body.billing] Required; [body.customer] Required"
        })
    );

    let (status, body) = post(
        &restricted,
        "/api/auth/dodopayments/checkout-session",
        json!({"slug": "missing"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"message": "Product not found"}));

    let (status, body) = post(
        &restricted,
        "/api/auth/dodopayments/checkout-session",
        json!({"slug": "pro"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body,
        json!({"message": "You must be logged in to checkout"})
    );

    let public = fixture(vec![checkout(false)], false, false).await;
    let (status, body) = post(
        &public,
        "/api/auth/dodopayments/checkout-session",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({"message": "Neither product_cart nor slug was provided"})
    );
    assert!(restricted.client.calls().await.is_empty());
    assert!(public.client.calls().await.is_empty());
}

struct FailingProducts;

#[async_trait]
impl DodoProductsProvider for FailingProducts {
    async fn products(&self) -> Result<Vec<lucid_auth::DodoProduct>, DodoPaymentsCallbackError> {
        Err(DodoPaymentsCallbackError::new("resolver failed"))
    }
}

#[tokio::test]
async fn dynamic_product_callback_failure_remains_an_unhandled_empty_500() {
    let checkout = DodoPaymentsFeature::Checkout(DodoCheckoutOptions {
        products: Some(DodoProducts::dynamic(Arc::new(FailingProducts))),
        ..DodoCheckoutOptions::default()
    });
    let fixture = fixture(vec![checkout], false, false).await;
    let (status, body) = post(
        &fixture,
        "/api/auth/dodopayments/checkout-session",
        json!({"slug": "pro"}),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, serde_json::Value::Null);
}
