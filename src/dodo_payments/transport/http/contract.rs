use super::*;
use axum::{
    Json, Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::any,
};
use http_body_util::BodyExt;
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: String,
    path_and_query: String,
    authorization: Option<String>,
    user_agent: Option<String>,
    retry_count: Option<String>,
    timeout: Option<String>,
    stainless_lang: Option<String>,
    stainless_package_version: Option<String>,
    idempotency_key: Option<String>,
    body: Value,
}

async fn capture(
    State(captured): State<Arc<Mutex<Option<CapturedRequest>>>>,
    request: Request,
) -> Json<Value> {
    let method = request.method().to_string();
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(ToString::to_string)
        .unwrap();
    let authorization = header(request.headers(), "authorization");
    let user_agent = header(request.headers(), "user-agent");
    let retry_count = header(request.headers(), "x-stainless-retry-count");
    let timeout = header(request.headers(), "x-stainless-timeout");
    let stainless_lang = header(request.headers(), "x-stainless-lang");
    let stainless_package_version = header(request.headers(), "x-stainless-package-version");
    let idempotency_key = header(request.headers(), "idempotency-key");
    let bytes = request.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    *captured.lock().unwrap() = Some(CapturedRequest {
        method,
        path_and_query,
        authorization,
        user_agent,
        retry_count,
        timeout,
        stainless_lang,
        stainless_package_version,
        idempotency_key,
        body,
    });
    Json(json!({"customer_id": "cus_1"}))
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

async fn server(router: Router) -> url::Url {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    url::Url::parse(&format!("http://{address}/api/")).unwrap()
}

#[tokio::test]
async fn sends_bearer_json_and_matches_the_pinned_idempotency_quirk() {
    let captured = Arc::new(Mutex::new(None));
    let base_url = server(
        Router::new()
            .fallback(any(capture))
            .with_state(captured.clone()),
    )
    .await;
    let transport = DodoPaymentsHttpTransport::new(DodoPaymentsProviderConfig::with_base_url(
        "  dodo_secret\n",
        DodoPaymentsEnvironment::Test,
        base_url,
    ));

    let response = transport
        .send(
            DodoPaymentsTransportRequest::post("customers/customer%2F1", json!({"name": "Ada"}))
                .with_idempotency_key(Some(" user_1\r")),
        )
        .await
        .unwrap();
    assert_eq!(response["customer_id"], "cus_1");
    let captured = captured.lock().unwrap().clone().unwrap();
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path_and_query, "/api/customers/customer%2F1");
    assert_eq!(
        captured.authorization.as_deref(),
        Some("Bearer dodo_secret")
    );
    assert_eq!(
        captured.user_agent.as_deref(),
        Some("DodoPayments/JS 2.47.0")
    );
    assert_eq!(captured.retry_count.as_deref(), Some("0"));
    assert_eq!(captured.timeout.as_deref(), Some("60"));
    assert_eq!(captured.stainless_lang.as_deref(), Some("rust"));
    assert_eq!(
        captured.stainless_package_version.as_deref(),
        Some("2.47.0")
    );
    assert_eq!(captured.idempotency_key, None);
    assert_eq!(captured.body, json!({"name": "Ada"}));
    let debug = format!("{transport:?}");
    assert!(!debug.contains("dodo_secret"));
}

#[tokio::test]
async fn percent_encodes_query_components_like_the_sdk() {
    let captured = Arc::new(Mutex::new(None));
    let base_url = server(
        Router::new()
            .fallback(any(capture))
            .with_state(captured.clone()),
    )
    .await;
    let transport = DodoPaymentsHttpTransport::new(DodoPaymentsProviderConfig::with_base_url(
        "key",
        DodoPaymentsEnvironment::Live,
        base_url,
    ));
    transport
        .send(DodoPaymentsTransportRequest::get(
            "events",
            vec![("event_name".into(), "api call/+".into())],
        ))
        .await
        .unwrap();
    assert_eq!(
        captured.lock().unwrap().as_ref().unwrap().path_and_query,
        "/api/events?event_name=api%20call%2F%2B"
    );
}

#[tokio::test]
async fn rejects_oversized_and_redacts_provider_error_bodies() {
    async fn oversized() -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("x".repeat(64)))
            .unwrap()
    }
    let base_url = server(Router::new().fallback(any(oversized))).await;
    let transport = DodoPaymentsHttpTransport::with_limits(
        DodoPaymentsProviderConfig::with_base_url("key", DodoPaymentsEnvironment::Test, base_url),
        Duration::from_secs(1),
        8,
    )
    .unwrap();
    let error = transport
        .send(DodoPaymentsTransportRequest::get("customers", Vec::new()))
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "Dodo Payments response exceeded limit");

    async fn denied() -> (StatusCode, &'static str) {
        (StatusCode::UNAUTHORIZED, "api key and customer details")
    }
    let base_url = server(Router::new().fallback(any(denied))).await;
    let transport = DodoPaymentsHttpTransport::new(DodoPaymentsProviderConfig::with_base_url(
        "key",
        DodoPaymentsEnvironment::Test,
        base_url,
    ));
    let error = transport
        .send(DodoPaymentsTransportRequest::get("customers", Vec::new()))
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(401));
    assert!(!format!("{error:?}").contains("customer details"));
}

#[test]
fn rejects_unbounded_transport_configuration() {
    let config = DodoPaymentsProviderConfig::test("key");
    assert!(DodoPaymentsHttpTransport::with_limits(config.clone(), Duration::ZERO, 10).is_err());
    assert!(DodoPaymentsHttpTransport::with_limits(config, Duration::from_secs(1), 0).is_err());
}

#[path = "contract/retry.rs"]
mod retry_contract;
