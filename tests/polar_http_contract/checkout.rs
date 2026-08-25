use crate::support::{fixture, post, selective_app};
use async_trait::async_trait;
use axum::http::StatusCode;
use lucid_auth::{
    CheckoutOptions, PolarCallbackError, PolarFeature, PolarProduct, PolarProducts,
    PolarProductsProvider,
};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn checkout_enforces_auth_and_resolves_slug_before_auth_rejection() {
    let fixture = fixture().await;
    let missing_product = post(
        &fixture.app,
        "/api/auth/checkout",
        None,
        json!({ "slug": "missing" }),
    )
    .await;
    assert_eq!(missing_product.0, StatusCode::BAD_REQUEST);
    assert_eq!(missing_product.2["message"], "Product not found");

    let logged_out = post(
        &fixture.app,
        "/api/auth/checkout",
        None,
        json!({ "slug": "pro" }),
    )
    .await;
    assert_eq!(logged_out.0, StatusCode::UNAUTHORIZED);
    assert_eq!(logged_out.2["message"], "You must be logged in to checkout");

    let anonymous = post(
        &fixture.app,
        "/api/auth/checkout",
        Some(&fixture.anonymous_cookie),
        json!({ "products": "product_pro" }),
    )
    .await;
    assert_eq!(anonymous.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        anonymous.2["message"],
        "Anonymous users are not allowed to checkout"
    );
}

#[tokio::test]
async fn checkout_matches_coercion_metadata_url_theme_and_sdk_request_shape() {
    let fixture = fixture().await;
    let response = post(
        &fixture.app,
        "/api/auth/checkout",
        Some(&fixture.cookie),
        json!({
            "slug": "pro",
            "referenceId": "synthetic",
            "metadata": { "referenceId": "body-wins", "emoji": "😀" },
            "customFieldData": { "team": 4 },
            "allowDiscountCodes": "false",
            "redirect": "",
            "returnUrl": "/return",
            "allowTrial": true,
            "trialInterval": "month",
            "trialIntervalCount": 2
        }),
    )
    .await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(
        response.2,
        json!({
            "url": "https://buy.polar.test/session?keep=1&theme=dark",
            "redirect": false
        })
    );
    let calls = fixture.client.calls("checkout").await;
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0]["external_customer_id"],
        fixture.user_id.to_string()
    );
    assert_eq!(calls[0]["products"], json!(["product_pro"]));
    assert_eq!(
        calls[0]["success_url"],
        "http://localhost/configured-success"
    );
    assert_eq!(calls[0]["return_url"], "http://localhost/return");
    assert_eq!(calls[0]["metadata"]["referenceId"], "body-wins");
    assert_eq!(calls[0]["custom_field_data"]["team"], 4);
    assert_eq!(calls[0]["allow_discount_codes"], true);
    assert_eq!(calls[0]["trial_interval"], "month");
}

#[tokio::test]
async fn checkout_validation_and_provider_failure_use_exact_statuses() {
    let fixture = fixture().await;
    let invalid = post(
        &fixture.app,
        "/api/auth/checkout",
        Some(&fixture.cookie),
        json!({ "successUrl": "relative", "trialIntervalCount": 0 }),
    )
    .await;
    assert_eq!(invalid.0, StatusCode::BAD_REQUEST);

    let unsafe_origin = post(
        &fixture.app,
        "/api/auth/checkout",
        Some(&fixture.cookie),
        json!({ "successUrl": "//untrusted.example/steal" }),
    )
    .await;
    assert_eq!(unsafe_origin.0, StatusCode::FORBIDDEN);

    let too_long = "😀".repeat(251);
    let invalid_metadata = post(
        &fixture.app,
        "/api/auth/checkout",
        Some(&fixture.cookie),
        json!({ "metadata": { "value": too_long } }),
    )
    .await;
    assert_eq!(invalid_metadata.0, StatusCode::BAD_REQUEST);

    fixture.client.fail_next("provider unavailable").await;
    let failed = post(
        &fixture.app,
        "/api/auth/checkout",
        Some(&fixture.cookie),
        json!({ "products": [] }),
    )
    .await;
    assert_eq!(failed.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(failed.2["message"], "Checkout creation failed");
}

#[tokio::test]
async fn dynamic_product_resolver_failure_uses_the_frameworks_bare_500() {
    let app = selective_app(vec![PolarFeature::Checkout(CheckoutOptions {
        products: Some(PolarProducts::dynamic(Arc::new(FailingProducts))),
        ..CheckoutOptions::default()
    })]);
    let response = post(&app, "/api/auth/checkout", None, json!({ "slug": "pro" })).await;
    assert_eq!(response.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response.2, serde_json::Value::Null);
}

struct FailingProducts;

#[async_trait]
impl PolarProductsProvider for FailingProducts {
    async fn products(&self) -> Result<Vec<PolarProduct>, PolarCallbackError> {
        Err(PolarCallbackError::new("resolver failed"))
    }
}
