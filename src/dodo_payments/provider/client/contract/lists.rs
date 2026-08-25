use super::*;
use crate::dodo_payments::{DodoPaymentStatus, DodoSubscriptionStatus, DodoUsageEvent};
use serde_json::{Map, json};

#[tokio::test]
async fn provider_lists_and_usage_preserve_items_and_wire_queries() {
    let payment_items = json!([{"id": "pay_1", "unknown": {"kept": true}}]);
    let subscription_items = json!([{"id": "sub_1", "status": "future_status"}]);
    let usage_items = json!([{"event_id": "evt_1", "metadata": {"nested": [1]}}]);
    let transport = Arc::new(RecordingTransport::new([
        json!({"items": payment_items}),
        json!({"items": subscription_items}),
        json!({"ingested_count": 1, "provider": "kept"}),
        json!({"items": usage_items}),
    ]));
    let client = DodoPaymentsHttpClient::with_transport(transport.clone());

    let payments = client
        .list_payments(DodoPaymentListRequest {
            customer_id: "cus_1".into(),
            page_number: Some(0.0),
            page_size: Some(20.0),
            status: Some(DodoPaymentStatus::RequiresCustomerAction),
        })
        .await
        .unwrap();
    let subscriptions = client
        .list_subscriptions(DodoSubscriptionListRequest {
            customer_id: "cus_1".into(),
            page_number: None,
            page_size: None,
            status: Some(DodoSubscriptionStatus::OnHold),
        })
        .await
        .unwrap();
    let ingestion = client
        .ingest_usage(DodoUsageIngestRequest {
            events: vec![DodoUsageEvent {
                customer_id: "cus_1".into(),
                event_id: "evt_1".into(),
                event_name: "api_call".into(),
                metadata: Some(Some(Map::from_iter([("tokens".into(), json!(3))]))),
                timestamp: Some("2026-08-25T12:00:00.000Z".into()),
            }],
        })
        .await
        .unwrap();
    let usage = client
        .list_usage(DodoUsageListRequest {
            customer_id: Some("cus_1".into()),
            page_number: Some(2.0),
            page_size: Some(10.0),
            event_name: Some("api call".into()),
            meter_id: Some("meter/1".into()),
            start: Some("start".into()),
            end: Some("end".into()),
        })
        .await
        .unwrap();

    assert_eq!(payments.items, payment_items.as_array().unwrap().clone());
    assert_eq!(
        subscriptions.items,
        subscription_items.as_array().unwrap().clone()
    );
    assert_eq!(ingestion.ingested_count, 1);
    assert_eq!(usage.items, usage_items.as_array().unwrap().clone());
    let requests = transport.requests();
    assert_eq!(
        requests[0].query,
        [
            ("customer_id".into(), "cus_1".into()),
            ("page_number".into(), "0".into()),
            ("page_size".into(), "20".into()),
            ("status".into(), "requires_customer_action".into()),
        ]
    );
    assert_eq!(requests[1].query[1].1, "on_hold");
    assert_eq!(requests[2].path, "events/ingest");
    assert_eq!(requests[3].path, "events");
}
