use super::*;
use serde_json::json;

#[tokio::test]
async fn checkout_and_legacy_creation_forward_json_without_schema_loss() {
    let transport = Arc::new(RecordingTransport::new([
        json!({"is_recurring": true, "provider_field": [1, 2]}),
        json!({
            "session_id": "cks_1",
            "checkout_url": "https://checkout.test/new",
            "provider_field": 1
        }),
        json!({"payment_link": "https://checkout.test/pay", "payment": {"kept": true}}),
        json!({"payment_link": "https://checkout.test/sub", "subscription": {"kept": true}}),
    ]));
    let client = DodoPaymentsHttpClient::with_transport(transport.clone());

    let product = client.retrieve_product("product/one").await.unwrap();
    assert!(product.is_recurring);
    assert_eq!(product.value["provider_field"], json!([1, 2]));
    let checkout_body = json!({"nested": {"unknown": [true, null, 3]}});
    client
        .create_checkout_session(checkout_body.clone())
        .await
        .unwrap();
    client
        .create_payment(json!({"payment": "body"}))
        .await
        .unwrap();
    client
        .create_subscription(json!({"subscription": "body"}))
        .await
        .unwrap();

    let requests = transport.requests();
    assert_eq!(requests[0].path, "products/product%2Fone");
    assert_eq!(requests[1].path, "checkouts");
    assert_eq!(requests[1].body, Some(checkout_body));
    assert_eq!(requests[2].path, "payments");
    assert_eq!(requests[3].path, "subscriptions");
}

#[test]
fn debug_only_reveals_the_non_secret_environment() {
    let transport = Arc::new(RecordingTransport::new([]));
    let client = DodoPaymentsHttpClient::with_transport(transport);
    assert_eq!(client.environment(), DodoPaymentsEnvironment::Test);
    assert!(format!("{client:?}").contains("Test"));
}
