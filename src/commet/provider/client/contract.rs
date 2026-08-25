use super::*;
use crate::commet::{CommetHttpMethod, CommetUsageProperty};
use serde_json::{Map, Number, json};
use std::{collections::VecDeque, sync::Mutex};

struct RecordingTransport {
    requests: Mutex<Vec<CommetTransportRequest>>,
    responses: Mutex<VecDeque<Value>>,
}

impl RecordingTransport {
    fn with_response_count(count: usize) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(
                (0..count)
                    .map(|index| json!({"raw": index, "unknown": {"kept": true}}))
                    .collect(),
            ),
        }
    }

    fn requests(&self) -> Vec<CommetTransportRequest> {
        self.requests.lock().unwrap().clone()
    }
}

#[async_trait]
impl CommetTransport for RecordingTransport {
    async fn send(&self, request: CommetTransportRequest) -> Result<Value, CommetProviderError> {
        self.requests.lock().unwrap().push(request);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| CommetProviderError::new("missing test response"))
    }
}

#[tokio::test]
async fn customer_calls_match_sdk_paths_queries_and_omitted_fields() {
    let transport = Arc::new(RecordingTransport::with_response_count(4));
    let client = CommetHttpClient::with_transport(transport.clone());

    let listed = client.list_customers("external /id").await.unwrap();
    assert_eq!(listed["unknown"]["kept"], true);
    client
        .create_customer(CommetCustomerCreate {
            email: "ada@example.com".into(),
            id: Some("user_1".into()),
            full_name: Some("Ada".into()),
            metadata: Some(json!({"nested": [1, true]})),
        })
        .await
        .unwrap();
    client
        .update_customer(
            "customer/one",
            CommetCustomerUpdate {
                email: Some("new@example.com".into()),
                full_name: None,
            },
        )
        .await
        .unwrap();
    client.create_portal_session("user_1").await.unwrap();

    let requests = transport.requests();
    assert_eq!(
        requests[0],
        CommetTransportRequest::get(
            "/customers",
            vec![("externalId".into(), "external /id".into())]
        )
    );
    assert_eq!(requests[1].path, "/customers");
    assert_eq!(
        requests[1].body,
        Some(json!({
            "email": "ada@example.com",
            "id": "user_1",
            "fullName": "Ada",
            "metadata": {"nested": [1, true]}
        }))
    );
    assert_eq!(requests[2].path, "/customers/customer/one");
    assert_eq!(requests[2].method, CommetHttpMethod::Patch);
    assert_eq!(requests[2].body, Some(json!({"email": "new@example.com"})));
    assert_eq!(requests[3].path, "/portal/sessions");
    assert_eq!(requests[3].body, Some(json!({"customerId": "user_1"})));
}

#[tokio::test]
async fn billing_calls_match_sdk_paths_and_preserve_json_numbers() {
    let transport = Arc::new(RecordingTransport::with_response_count(10));
    let client = CommetHttpClient::with_transport(transport.clone());

    client.get_active_subscription("user/one").await.unwrap();
    client
        .cancel_subscription(
            "subscription/one",
            CommetSubscriptionCancel {
                reason: Some(String::new()),
                immediate: Some(false),
            },
        )
        .await
        .unwrap();
    client.list_feature_access("user/one").await.unwrap();
    client
        .get_feature_access("user/one", "feature/one")
        .await
        .unwrap();
    client.check_usage("user/one", "feature/one").await.unwrap();
    client
        .create_usage_event(
            CommetUsageEvent {
                feature_code: "api".into(),
                customer_id: "user/one".into(),
                value: Some(Number::from(1)),
                properties: Some(vec![CommetUsageProperty {
                    property: "0".into(),
                    value: "first".into(),
                }]),
            },
            Some("usage-key"),
        )
        .await
        .unwrap();
    client.list_seat_balances("user/one").await.unwrap();
    client.add_seats(seat(Number::from(2))).await.unwrap();
    client
        .remove_seats(seat(Number::from_f64(1.5).unwrap()))
        .await
        .unwrap();
    client.set_all_seats(all_seats()).await.unwrap();

    let requests = transport.requests();
    assert_eq!(requests[0].path, "/subscriptions/active");
    assert_eq!(
        requests[0].query,
        [("customerId".into(), "user/one".into())]
    );
    assert_eq!(requests[1].path, "/subscriptions/subscription/one/cancel");
    assert_eq!(
        requests[1].body,
        Some(json!({"reason": "", "immediate": false}))
    );
    assert_eq!(requests[2].path, "/feature-access");
    assert_eq!(requests[3].path, "/feature-access/feature/one");
    assert_eq!(requests[4].path, "/usage/check");
    assert_eq!(
        requests[4].body,
        Some(json!({"customerId": "user/one", "featureCode": "feature/one"}))
    );
    assert_eq!(requests[5].path, "/usage/events");
    assert_eq!(requests[5].idempotency_key.as_deref(), Some("usage-key"));
    assert_eq!(requests[5].body.as_ref().unwrap()["value"], json!(1));
    assert_eq!(requests[6].path, "/seats/balances");
    assert_eq!(requests[7].path, "/seats");
    assert_eq!(requests[7].body.as_ref().unwrap()["count"], json!(2));
    assert_eq!(requests[8].path, "/seats/remove");
    assert_eq!(requests[8].body.as_ref().unwrap()["count"], json!(1.5));
    assert_eq!(requests[9].path, "/seats/bulk");
    assert_eq!(requests[9].method, CommetHttpMethod::Put);
    assert_eq!(requests[9].body.as_ref().unwrap()["seats"]["negative"], -1);
}

fn seat(count: Number) -> CommetSeatMutation {
    CommetSeatMutation {
        customer_id: "user/one".into(),
        feature_code: "members".into(),
        count,
    }
}

fn all_seats() -> CommetSeatSetAll {
    CommetSeatSetAll {
        customer_id: "user/one".into(),
        seats: Map::from_iter([
            ("negative".into(), json!(-1)),
            ("fractional".into(), json!(0.25)),
        ]),
    }
}

#[tokio::test]
async fn set_seats_uses_put_and_empty_usage_keys_remain_absent_at_trait_boundary() {
    let transport = Arc::new(RecordingTransport::with_response_count(2));
    let client = CommetHttpClient::with_transport(transport.clone());
    client.set_seats(seat(Number::from(3))).await.unwrap();
    client
        .create_usage_event(
            CommetUsageEvent {
                feature_code: "api".into(),
                customer_id: "user".into(),
                value: None,
                properties: None,
            },
            Some(""),
        )
        .await
        .unwrap();

    let requests = transport.requests();
    assert_eq!(requests[0].method, CommetHttpMethod::Put);
    assert_eq!(requests[0].path, "/seats");
    assert_eq!(requests[1].idempotency_key, None);
}

#[test]
fn debug_output_does_not_expose_transport_internals() {
    let client =
        CommetHttpClient::with_transport(Arc::new(RecordingTransport::with_response_count(0)));
    assert_eq!(format!("{client:?}"), "CommetHttpClient { .. }");
}
