use super::support::{fixture, signed_request};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use lucid_auth::{CommetWebhookCallbacks, sign_commet_webhook};
use serde_json::json;

const PAYLOAD: &str = r#"{"data":{"id":"sub_1"},"event":"subscription.created","id":"evt_1"}"#;

fn assert_invalid(response: &super::support::WebhookResponse) {
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.body, r#"{"message":"Invalid webhook signature"}"#);
}

#[tokio::test]
async fn missing_malformed_and_mismatched_signatures_are_unauthorized() {
    let fixture = fixture(CommetWebhookCallbacks::default());
    let missing = Request::post("/api/auth/commet/webhooks")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(PAYLOAD))
        .unwrap();
    assert_invalid(&fixture.send(missing).await);

    for signature in ["not-hex", &"00".repeat(32)] {
        assert_invalid(&fixture.send(signed_request(PAYLOAD, Some(signature))).await);
    }
}

#[tokio::test]
async fn every_correctly_signed_json_falsy_value_is_unauthorized() {
    let fixture = fixture(CommetWebhookCallbacks::default());
    for body in ["null", "false", "0", r#""""#] {
        assert_invalid(&fixture.send(signed_request(body, None)).await);
    }
}

#[tokio::test]
async fn node_hex_uppercase_and_trailing_decode_quirks_are_accepted() {
    let fixture = fixture(CommetWebhookCallbacks::default());
    let exact = sign_commet_webhook(PAYLOAD, super::support::SECRET);
    for signature in [
        exact.to_uppercase(),
        format!("{exact}f"),
        format!("{exact}not-hex-and-ignored"),
    ] {
        let response = fixture
            .send(signed_request(PAYLOAD, Some(&signature)))
            .await;
        assert_eq!(response.status, StatusCode::OK, "signature {signature}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response.body).unwrap(),
            json!({"received": true}),
        );
    }
}

#[tokio::test]
async fn signed_malformed_json_is_rejected_before_signature_dispatch() {
    let body = "{";
    let response = fixture(CommetWebhookCallbacks::default())
        .send(signed_request(body, None))
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}
