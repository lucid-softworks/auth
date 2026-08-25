use super::*;
use crate::dodo_payments::transport::DodoPaymentsHttpMethod;
use serde_json::json;
use std::collections::BTreeMap;

#[tokio::test]
async fn customer_operations_match_sdk_paths_bodies_and_idempotency() {
    let transport = Arc::new(RecordingTransport::new([
        json!({"items": [{"customer_id": "cus_1", "extra": {"kept": true}}]}),
        json!({"customer_id": "cus_2", "created_at": "kept"}),
        json!({"customer_id": "cus_2", "phone_number": null}),
        json!({"link": "https://portal.test/customer", "extra": 1}),
    ]));
    let client = DodoPaymentsHttpClient::with_transport(transport.clone());

    let page = client
        .list_customers(DodoCustomerListRequest {
            email: "ada+test@example.com".into(),
        })
        .await
        .unwrap();
    assert_eq!(page.items[0].value["extra"]["kept"], true);
    client
        .create_customer(
            DodoCustomerCreateRequest {
                email: "ada@example.com".into(),
                name: "Ada".into(),
                metadata: Some(BTreeMap::from([("plan".into(), "pro".into())])),
                phone_number: Some(None),
            },
            Some("user_1"),
        )
        .await
        .unwrap();
    client
        .update_customer(
            "customer /one",
            DodoCustomerUpdateRequest {
                name: Some(Some("Ada Lovelace".into())),
                ..DodoCustomerUpdateRequest::default()
            },
        )
        .await
        .unwrap();
    client
        .create_customer_portal("customer /one")
        .await
        .unwrap();

    let requests = transport.requests();
    assert_eq!(requests[0].method, DodoPaymentsHttpMethod::Get);
    assert_eq!(
        requests[0].query,
        [("email".into(), "ada+test@example.com".into())]
    );
    assert_eq!(requests[1].idempotency_key.as_deref(), Some("user_1"));
    assert_eq!(
        requests[1].body,
        Some(json!({
            "email": "ada@example.com", "name": "Ada",
            "metadata": {"plan": "pro"}, "phone_number": null
        }))
    );
    assert_eq!(requests[2].path, "customers/customer%20%2Fone");
    assert_eq!(requests[2].method, DodoPaymentsHttpMethod::Patch);
    assert_eq!(
        requests[3].path,
        "customers/customer%20%2Fone/customer-portal/session"
    );
    assert_eq!(requests[3].body, None);
}
