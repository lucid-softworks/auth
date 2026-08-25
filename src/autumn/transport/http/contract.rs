use super::*;
use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::any,
};
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug)]
struct CapturedRequest {
    path: String,
    headers: HeaderMap,
    body: Value,
}

#[derive(Clone)]
struct MockState {
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    status: StatusCode,
    content_type: &'static str,
    body: &'static str,
}

async fn capture(State(state): State<MockState>, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    let headers = request.headers().clone();
    let body = to_bytes(request.into_body(), 1024 * 1024)
        .await
        .ok()
        .and_then(|body| serde_json::from_slice(&body).ok())
        .unwrap_or(Value::Null);
    state.captured.lock().unwrap().push(CapturedRequest {
        path,
        headers,
        body,
    });
    (
        state.status,
        [(header::CONTENT_TYPE, state.content_type)],
        state.body,
    )
        .into_response()
}

async fn mock_server(
    status: StatusCode,
    content_type: &'static str,
    body: &'static str,
) -> (Url, Arc<Mutex<Vec<CapturedRequest>>>) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        captured: captured.clone(),
        status,
        content_type,
        body,
    };
    let app = Router::new().fallback(any(capture)).with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (
        Url::parse(&format!("http://{address}/autumn-proxy")).unwrap(),
        captured,
    )
}

#[test]
fn joins_paths_without_discarding_a_configured_base_path() {
    let base = Url::parse("https://example.test/nested/autumn").unwrap();
    assert_eq!(
        operation_url(&base, AutumnOperation::ListPlans)
            .unwrap()
            .as_str(),
        "https://example.test/nested/autumn/v1/plans.list"
    );
}

#[test]
fn bearer_prefix_detection_is_case_insensitive_and_does_not_duplicate() {
    assert_eq!(bearer_value("secret"), "Bearer secret");
    assert_eq!(bearer_value("Bearer secret"), "Bearer secret");
    assert_eq!(bearer_value("bEaReR secret"), "bEaReR secret");
}

#[test]
fn only_the_exact_json_media_type_matches() {
    assert!(is_application_json("application/json"));
    assert!(is_application_json("Application/JSON; Charset=UTF-8"));
    assert!(!is_application_json("application/problem+json"));
    assert!(!is_application_json("text/json"));
}

#[tokio::test]
async fn sends_the_exact_generated_sdk_request_headers_and_preserves_base_paths() {
    let (base, captured) = mock_server(
        StatusCode::UNPROCESSABLE_ENTITY,
        "application/json",
        r#"{"message":"invalid plan query","code":"invalid_query"}"#,
    )
    .await;
    let error = AutumnHttpClient::new()
        .execute(
            AutumnOperation::ListPlans,
            json!({}),
            "bEaReR provider-secret",
            &base,
        )
        .await
        .unwrap_err();

    assert_eq!(error.status, Some(422));
    assert_eq!(error.message, "invalid plan query");
    assert_eq!(error.code, "invalid_query");
    let captured = captured.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].path, "/autumn-proxy/v1/plans.list");
    assert_eq!(
        captured[0].headers[header::AUTHORIZATION],
        "bEaReR provider-secret"
    );
    assert_eq!(captured[0].headers[header::ACCEPT], "application/json");
    assert_eq!(
        captured[0].headers[header::CONTENT_TYPE],
        "application/json"
    );
    assert_eq!(captured[0].headers[header::USER_AGENT], USER_AGENT);
    assert_eq!(captured[0].headers["x-api-version"], "2.3.0");
    assert_eq!(captured[0].body, json!({}));
}

#[tokio::test]
async fn outbound_schema_errors_include_the_generated_zod_cause() {
    let base = Url::parse("https://autumn.example.test/").unwrap();
    let error = AutumnHttpClient::new()
        .execute(
            AutumnOperation::AggregateEvents,
            json!({
                "customerId": "customer_native",
                "featureId": "feature_native",
                "maxGroups": 1.5
            }),
            "secret",
            &base,
        )
        .await
        .unwrap_err();
    assert_eq!(error.status, None);
    assert_eq!(error.code, "internal_error");
    assert_eq!(
        error.message,
        "Input validation failed: [\n  {\n    \"expected\": \"int\",\n    \"format\": \"safeint\",\n    \"code\": \"invalid_type\",\n    \"path\": [\n      \"maxGroups\"\n    ],\n    \"message\": \"Invalid input: expected int, received number\"\n  }\n]"
    );
}

#[tokio::test]
async fn rejects_json_suffix_content_types_even_on_http_200() {
    let (base, _) = mock_server(
        StatusCode::OK,
        "application/problem+json",
        r#"{"detail":"not a generated response"}"#,
    )
    .await;
    let error = AutumnHttpClient::new()
        .execute(AutumnOperation::ListPlans, json!({}), "secret", &base)
        .await
        .unwrap_err();
    assert_eq!(error.status, Some(200));
    assert_eq!(error.code, "autumn_api_error");
    assert_eq!(
        error.message,
        "Unexpected Status or Content-Type: Status 200 Content-Type application/problem+json. Body: {\"detail\":\"not a generated response\"}"
    );
}

#[tokio::test]
async fn ordinary_transport_failures_are_synthetic_http_555() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let base = Url::parse(&format!("http://{address}/")).unwrap();
    let error = AutumnHttpClient::new()
        .execute(AutumnOperation::ListPlans, json!({}), "secret", &base)
        .await
        .unwrap_err();
    assert_eq!(error.status, Some(555));
    assert_eq!(error.code, "autumn_api_error");
    assert_eq!(
        error.message,
        "API error occurred: Status 555 Content-Type \"\". Body: \"\""
    );
}

#[tokio::test]
async fn response_limits_are_enforced_as_synthetic_transport_failures() {
    assert!(AutumnHttpClient::with_limits(Duration::ZERO, 1).is_err());
    assert!(AutumnHttpClient::with_limits(Duration::from_secs(1), 0).is_err());

    let (base, _) = mock_server(
        StatusCode::BAD_REQUEST,
        "text/plain",
        "response exceeds four bytes",
    )
    .await;
    let error = AutumnHttpClient::with_limits(Duration::from_secs(1), 4)
        .unwrap()
        .execute(AutumnOperation::ListPlans, json!({}), "secret", &base)
        .await
        .unwrap_err();
    assert_eq!(error.status, Some(555));
    assert_eq!(
        error.message,
        "API error occurred: Status 555 Content-Type \"\". Body: \"\""
    );
}

#[tokio::test]
async fn the_two_generated_fail_open_operations_return_exact_decoded_bodies() {
    let (base, _) = mock_server(
        StatusCode::SERVICE_UNAVAILABLE,
        "text/plain",
        "temporarily unavailable",
    )
    .await;
    let client = AutumnHttpClient::new();
    let customer_error = client
        .execute(
            AutumnOperation::GetOrCreateCustomer,
            json!({
                "customerId": "user-1",
                "errorOnNotFound": true,
                "expand": ["balances.feature"]
            }),
            "secret",
            &base,
        )
        .await
        .unwrap_err();
    assert_eq!(customer_error.status, Some(200));
    assert_eq!(customer_error.message, "Response validation failed");
    assert_eq!(customer_error.code, "autumn_api_error");

    let entity = client
        .execute(
            AutumnOperation::GetEntity,
            json!({"customerId": "user-1", "entityId": "entity-1"}),
            "secret",
            &base,
        )
        .await
        .unwrap();
    assert_eq!(
        entity,
        json!({
            "id": null,
            "name": null,
            "customerId": null,
            "featureId": null,
            "createdAt": 0,
            "env": "live",
            "subscriptions": [],
            "purchases": [],
            "balances": {},
            "flags": {}
        })
    );
}
