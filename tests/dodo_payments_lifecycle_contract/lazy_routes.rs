use super::support::{LifecycleCall, fixture, get, post};
use axum::http::StatusCode;
use lucid_auth::AuthStore;
use serde_json::json;

async fn wait_for_customer_id(fixture: &super::support::Fixture, expected: &str) {
    for _ in 0..20 {
        let user = fixture
            .store
            .find_user_by_id(&fixture.user_id)
            .await
            .unwrap()
            .unwrap();
        if user
            .additional_fields
            .get("dodoCustomerId")
            .and_then(serde_json::Value::as_str)
            == Some(expected)
        {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("dodoCustomerId was not persisted");
}

#[tokio::test]
async fn portal_resolves_an_existing_customer_and_backfills_the_user() {
    let fixture = fixture(Some("customer_existing")).await;

    let (status, body) = get(&fixture, "/api/auth/dodopayments/customer/portal").await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"url": "https://portal.dodo.test/lazy", "redirect": true})
    );
    assert_eq!(
        fixture.client.calls().await,
        [
            LifecycleCall::ListCustomers(lucid_auth::DodoCustomerListRequest {
                email: "lifecycle@example.test".into(),
            }),
            LifecycleCall::Portal("customer_existing".into()),
        ]
    );
    wait_for_customer_id(&fixture, "customer_existing").await;
}

#[tokio::test]
async fn usage_creates_and_backfills_a_missing_customer_with_callback_params() {
    let fixture = fixture(None).await;

    let (status, body) = post(
        &fixture,
        "/api/auth/dodopayments/usage/ingest",
        json!({"event_id": "event_lazy", "event_name": "api_call"}),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"ingested_count": 1}));
    let calls = fixture.client.calls().await;
    assert_eq!(calls.len(), 3);
    assert!(matches!(calls[0], LifecycleCall::ListCustomers(_)));
    let LifecycleCall::CreateCustomer(request, idempotency_key) = &calls[1] else {
        panic!("expected lazy customer creation, got {:?}", calls[1]);
    };
    let expected_key = fixture.user_id.to_string();
    assert_eq!(idempotency_key.as_deref(), Some(expected_key.as_str()));
    assert_eq!(request.email, "lifecycle@example.test");
    assert_eq!(request.name, "Lifecycle Owner");
    assert_eq!(
        request.metadata,
        Some(std::collections::BTreeMap::from([(
            "source".into(),
            "lazy-route".into()
        )]))
    );
    assert_eq!(request.phone_number, Some(None));
    let LifecycleCall::IngestUsage(request) = &calls[2] else {
        panic!("expected usage ingestion, got {:?}", calls[2]);
    };
    assert_eq!(request.events[0].customer_id, "customer_lazy_created");
    wait_for_customer_id(&fixture, "customer_lazy_created").await;
}
