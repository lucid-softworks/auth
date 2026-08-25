use super::support::{fixture, raw_request};
use axum::http::{StatusCode, header};
use lucid_auth::CommetWebhookCallbacks;
use serde_json::json;

#[tokio::test]
async fn omitted_body_is_a_message_only_bad_request() {
    let response = fixture(CommetWebhookCallbacks::default())
        .send(raw_request(None, ""))
        .await;

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.headers[header::CONTENT_TYPE], "application/json");
    assert_eq!(response.body, r#"{"message":"Request body is required"}"#);
}

#[tokio::test]
async fn empty_and_malformed_json_are_coded_bad_requests() {
    let fixture = fixture(CommetWebhookCallbacks::default());
    for body in ["", "{"] {
        let response = fixture
            .send(raw_request(Some("application/json"), body))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "body {body:?}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response.body).unwrap(),
            json!({
                "code": "BAD_REQUEST",
                "message": "Invalid JSON in request body",
            }),
            "body {body:?}",
        );
    }
}

#[tokio::test]
async fn wrong_content_type_has_the_exact_upstream_error() {
    let response = fixture(CommetWebhookCallbacks::default())
        .send(raw_request(Some("text/plain"), r#"{"event":"unknown"}"#))
        .await;

    assert_eq!(response.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&response.body).unwrap(),
        json!({
            "code": "UNSUPPORTED_MEDIA_TYPE",
            "message": "Content-Type \"text/plain\" is not allowed. Allowed types: application/json",
        }),
    );
}
