use super::support::{app, known_body, now, post, signed_post, unknown_body, webhook_secret};
use axum::http::{StatusCode, header};
use lucid_auth::DodoWebhookCallbacks;
use serde_json::json;

#[tokio::test]
async fn absent_body_is_an_exact_empty_json_internal_error() {
    let app = app(&webhook_secret(), DodoWebhookCallbacks::default());
    for body in [None, Some("")] {
        let response = post(&app, body, &[]).await;
        assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.headers[header::CONTENT_TYPE], "application/json");
        assert!(response.body.is_empty());
    }
}

#[tokio::test]
async fn empty_webhook_key_keeps_the_adapter_error() {
    let response = post(&app("", DodoWebhookCallbacks::default()), Some("{}"), &[]).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json(),
        json!({"message":"Webhook Error: DodoPayments webhook webhookKey not found"})
    );
}

#[tokio::test]
async fn every_required_signature_header_is_enforced() {
    let secret = webhook_secret();
    let app = app(&secret, DodoWebhookCallbacks::default());
    let body = unknown_body();
    let timestamp = now();
    let complete = [
        ("webhook-id", "evt_headers".to_owned()),
        ("webhook-timestamp", timestamp.to_string()),
        ("webhook-signature", "v1,unused".to_owned()),
    ];
    for omitted in 0..complete.len() {
        let headers = complete
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != omitted)
            .map(|(_, header)| header.clone())
            .collect::<Vec<_>>();
        let response = post(&app, Some(&body), &headers).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json(),
            json!({"message":"Webhook Error: Missing required headers"})
        );
    }
}

#[tokio::test]
async fn timestamp_tolerance_is_inclusive_and_rejects_beyond_both_bounds() {
    let secret = webhook_secret();
    let app = app(&secret, DodoWebhookCallbacks::default());
    let body = unknown_body();

    let accepted = signed_post(&app, "evt_boundary", now() + 300, &body, &secret).await;
    assert_eq!(accepted.status, StatusCode::OK);

    let stale = signed_post(&app, "evt_stale", now() - 301, &body, &secret).await;
    assert_eq!(stale.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        stale.json(),
        json!({"message":"Webhook Error: Message timestamp too old"})
    );

    let future = signed_post(&app, "evt_future", now() + 302, &body, &secret).await;
    assert_eq!(future.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        future.json(),
        json!({"message":"Webhook Error: Message timestamp too new"})
    );
}

#[tokio::test]
async fn invalid_signatures_are_rejected_before_payload_parsing() {
    let response = post(
        &app(&webhook_secret(), DodoWebhookCallbacks::default()),
        Some("{"),
        &[
            ("webhook-id", "evt_invalid".to_owned()),
            ("webhook-timestamp", now().to_string()),
            ("webhook-signature", "v1,aW52YWxpZA==".to_owned()),
        ],
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json(),
        json!({"message":"Webhook Error: No matching signature found"})
    );
}

#[tokio::test]
async fn signed_malformed_json_and_known_payloads_are_rejected() {
    let secret = webhook_secret();
    let app = app(&secret, DodoWebhookCallbacks::default());
    let malformed = signed_post(&app, "evt_json", now(), "{", &secret).await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        malformed.json(),
        json!({"message":"Webhook Error: EOF while parsing an object at line 1 column 1"})
    );

    let known = serde_json::from_str::<serde_json::Value>(&known_body()).unwrap();
    let malformed_known = json!({
        "business_id": known["business_id"],
        "type": known["type"],
        "timestamp": known["timestamp"],
        "data": {}
    })
    .to_string();
    let response = signed_post(&app, "evt_known", now(), &malformed_known, &secret).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json(),
        json!({"message":"Webhook Error: Invalid dunning.started payload"})
    );
}

#[tokio::test]
async fn unknown_events_remain_permissive() {
    let secret = webhook_secret();
    let response = signed_post(
        &app(&secret, DodoWebhookCallbacks::default()),
        "evt_unknown",
        now(),
        &unknown_body(),
        &secret,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json(), json!({"received":true}));
}
