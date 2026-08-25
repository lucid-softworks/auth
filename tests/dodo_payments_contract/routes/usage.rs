use super::super::support::{DodoCall, fixture, get, post};
use axum::http::StatusCode;
use lucid_auth::DodoPaymentsFeature;
use serde_json::json;

#[tokio::test]
async fn routes_preserve_explicit_null_metadata_and_meter_query_names() {
    let fixture = fixture(vec![DodoPaymentsFeature::Usage], true, true).await;
    let (status, body) = post(
        &fixture,
        "/api/auth/dodopayments/usage/ingest",
        json!({
            "event_id": "event_contract",
            "event_name": "api_call",
            "metadata": null
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"ingested_count": 1}));

    let (status, body) = get(
        &fixture,
        "/api/auth/dodopayments/usage/meters/list?page_number=4&page_size=25&event_name=api_call&meter_id=meter_api&start=2026-08-01&end=2026-08-31",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"items": [{"meter_id": "meter_contract"}]}));

    let calls = fixture.client.calls().await;
    let DodoCall::IngestUsage(request) = &calls[0] else {
        panic!("expected usage-ingest call, got {:?}", calls[0]);
    };
    assert_eq!(request.events.len(), 1);
    assert_eq!(request.events[0].customer_id, "cus_contract");
    assert_eq!(request.events[0].event_id, "event_contract");
    assert_eq!(request.events[0].event_name, "api_call");
    assert_eq!(request.events[0].metadata, Some(None));
    assert_eq!(request.events[0].timestamp, None);
    let DodoCall::ListUsage(request) = &calls[1] else {
        panic!("expected usage-list call, got {:?}", calls[1]);
    };
    assert_eq!(request.customer_id.as_deref(), Some("cus_contract"));
    assert_eq!(request.page_number, Some(4.0));
    assert_eq!(request.page_size, Some(25.0));
    assert_eq!(request.event_name.as_deref(), Some("api_call"));
    assert_eq!(request.meter_id.as_deref(), Some("meter_api"));
    assert_eq!(request.start.as_deref(), Some("2026-08-01"));
    assert_eq!(request.end.as_deref(), Some("2026-08-31"));
}
