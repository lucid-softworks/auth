use crate::support::{fixture, get, post};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn portal_get_post_auth_theme_and_return_url_match_contract() {
    let fixture = fixture().await;
    let missing = get(&fixture.app, "/api/auth/customer/portal", None).await;
    assert_eq!(missing.0, StatusCode::BAD_REQUEST);
    assert_eq!(missing.2["message"], "User not found");

    let anonymous = get(
        &fixture.app,
        "/api/auth/customer/portal",
        Some(&fixture.anonymous_cookie),
    )
    .await;
    assert_eq!(anonymous.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        anonymous.2["message"],
        "Anonymous users cannot access the portal"
    );

    let get_response = get(
        &fixture.app,
        "/api/auth/customer/portal",
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(get_response.0, StatusCode::OK);
    assert_eq!(get_response.2["redirect"], true);
    assert_eq!(
        get_response.2["url"],
        "https://polar.test/portal?keep=1&theme=dark"
    );

    let post_response = post(
        &fixture.app,
        "/api/auth/customer/portal",
        Some(&fixture.cookie),
        json!({ "redirect": false }),
    )
    .await;
    assert_eq!(post_response.0, StatusCode::OK);
    assert_eq!(post_response.2["redirect"], false);
    let sessions = fixture.client.calls("customer_session").await;
    assert_eq!(
        sessions[0]["return_url"],
        "https://app.example.test/account home?next=a%2Fb"
    );

    let strict = post(
        &fixture.app,
        "/api/auth/customer/portal",
        Some(&fixture.cookie),
        json!({ "redirect": "false" }),
    )
    .await;
    assert_eq!(strict.0, StatusCode::BAD_REQUEST);

    let explicit_null = post(
        &fixture.app,
        "/api/auth/customer/portal",
        Some(&fixture.cookie),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(explicit_null.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn customer_lists_forward_js_coercions_and_sdk_values() {
    let fixture = fixture().await;
    let state = get(
        &fixture.app,
        "/api/auth/customer/state",
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(state.0, StatusCode::OK);
    assert_eq!(state.2["id"], fixture.user_id.to_string());

    let benefits = get(
        &fixture.app,
        "/api/auth/customer/benefits/list?page=1.5&limit=0x10",
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(benefits.0, StatusCode::OK);
    assert_eq!(benefits.2["result"]["items"][0]["kind"], "benefit");
    let benefit_calls = fixture.client.calls("benefits").await;
    assert_eq!(benefit_calls[0]["query"]["page"], 1.5);
    assert_eq!(benefit_calls[0]["query"]["limit"], 16.0);

    let referenced = get(
        &fixture.app,
        "/api/auth/customer/subscriptions/list?referenceId=foreign-org&active=false&page=2",
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(referenced.0, StatusCode::OK);
    let reference_calls = fixture.client.calls("reference_subscriptions").await;
    assert_eq!(reference_calls[0]["referenceId"], "foreign-org");
    assert_eq!(reference_calls[0]["active"], true);

    let subscriptions = get(
        &fixture.app,
        "/api/auth/customer/subscriptions/list?active=",
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(subscriptions.0, StatusCode::OK);
    let subscription_calls = fixture.client.calls("customer_subscriptions").await;
    assert_eq!(subscription_calls[0]["query"]["active"], false);

    let orders = get(
        &fixture.app,
        "/api/auth/customer/orders/list?productBillingType=one_time&limit=3",
        Some(&fixture.cookie),
    )
    .await;
    assert_eq!(orders.0, StatusCode::OK);
    let order_calls = fixture.client.calls("orders").await;
    assert_eq!(order_calls[0]["query"]["product_billing_type"], "one_time");
}

#[tokio::test]
async fn usage_routes_require_a_user_and_forward_exact_event_shape() {
    let fixture = fixture().await;
    let missing = get(&fixture.app, "/api/auth/usage/meters/list", None).await;
    assert_eq!(missing.0, StatusCode::BAD_REQUEST);
    assert_eq!(missing.2["message"], "User not found");

    let meters = get(
        &fixture.app,
        "/api/auth/usage/meters/list?page=4",
        Some(&fixture.anonymous_cookie),
    )
    .await;
    assert_eq!(meters.0, StatusCode::OK);
    assert_eq!(meters.2["result"]["items"][0]["kind"], "meter");

    let ingestion = post(
        &fixture.app,
        "/api/auth/usage/ingest",
        Some(&fixture.cookie),
        json!({ "event": "tokens", "metadata": { "amount": 2, "cached": false } }),
    )
    .await;
    assert_eq!(ingestion.0, StatusCode::OK);
    assert_eq!(ingestion.2, json!({ "inserted": 1 }));
    let calls = fixture.client.calls("ingest").await;
    assert_eq!(calls[0]["events"][0]["name"], "tokens");
    assert_eq!(
        calls[0]["events"][0]["external_customer_id"],
        fixture.user_id.to_string()
    );
    assert_eq!(calls[0]["events"][0]["metadata"]["cached"], false);

    let invalid = post(
        &fixture.app,
        "/api/auth/usage/ingest",
        Some(&fixture.cookie),
        json!({ "event": "tokens", "metadata": { "nested": {} } }),
    )
    .await;
    assert_eq!(invalid.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn provider_failures_keep_each_official_message() {
    let fixture = fixture().await;
    for (path, message) in [
        (
            "/api/auth/customer/portal",
            "Customer portal creation failed",
        ),
        ("/api/auth/customer/state", "Subscriptions list failed"),
        ("/api/auth/customer/benefits/list", "Benefits list failed"),
        (
            "/api/auth/customer/subscriptions/list",
            "Polar subscriptions list failed",
        ),
        ("/api/auth/customer/orders/list", "Orders list failed"),
        ("/api/auth/usage/meters/list", "Meters list failed"),
    ] {
        fixture.client.fail_next("provider unavailable").await;
        let response = get(&fixture.app, path, Some(&fixture.cookie)).await;
        assert_eq!(response.0, StatusCode::INTERNAL_SERVER_ERROR, "{path}");
        assert_eq!(response.2["message"], message, "{path}");
    }
    fixture.client.fail_next("provider unavailable").await;
    let ingestion = post(
        &fixture.app,
        "/api/auth/usage/ingest",
        Some(&fixture.cookie),
        json!({ "event": "tokens", "metadata": {} }),
    )
    .await;
    assert_eq!(ingestion.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(ingestion.2["message"], "Ingestion failed");
}
