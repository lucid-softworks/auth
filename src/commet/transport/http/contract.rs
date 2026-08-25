use super::*;
use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::any,
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::net::TcpListener;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedRequest {
    method: String,
    path_and_query: String,
    api_key: String,
    api_version: String,
    content_type: String,
    user_agent: String,
    client_info: Option<String>,
    idempotency_key: Option<String>,
    body: String,
}

async fn server(app: Router) -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Url::parse(&format!("http://{address}/ignored/base/")).unwrap()
}

async fn capture(
    State(requests): State<Arc<Mutex<Vec<CapturedRequest>>>>,
    request: Request,
) -> axum::Json<Value> {
    let headers = request.headers().clone();
    let method = request.method().to_string();
    let path_and_query = request.uri().path_and_query().unwrap().as_str().to_owned();
    let body = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .unwrap();
    requests.lock().unwrap().push(CapturedRequest {
        method,
        path_and_query,
        api_key: text_header(&headers, "x-api-key").unwrap(),
        api_version: text_header(&headers, "commet-version").unwrap(),
        content_type: text_header(&headers, "content-type").unwrap(),
        user_agent: text_header(&headers, "user-agent").unwrap(),
        client_info: text_header(&headers, "commet-client-info"),
        idempotency_key: text_header(&headers, "idempotency-key"),
        body: String::from_utf8(body.to_vec()).unwrap(),
    });
    axum::Json(json!({"ok": true}))
}

fn text_header(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

#[tokio::test]
async fn sends_exact_version_json_and_native_user_agent_headers() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let transport = CommetHttpTransport::new(
        CommetProviderConfig::with_base_url(
            "ck_secret-key\n",
            server(
                Router::new()
                    .fallback(any(capture))
                    .with_state(requests.clone()),
            )
            .await,
        )
        .unwrap(),
    );
    transport
        .send(CommetTransportRequest::get(
            "/customers",
            vec![("externalId".into(), "customer /+".into())],
        ))
        .await
        .unwrap();
    transport
        .send(CommetTransportRequest::post(
            "/usage/events",
            json!({"value": 1}),
        ))
        .await
        .unwrap();
    transport
        .send(
            CommetTransportRequest::post("/usage/events", json!({"value": 2}))
                .with_idempotency_key(Some(" explicit-key\n")),
        )
        .await
        .unwrap();

    let captured = requests.lock().unwrap();
    assert_eq!(captured[0].method, "GET");
    assert_eq!(
        captured[0].path_and_query,
        "/api/v1/customers?externalId=customer+%2F%2B"
    );
    assert_eq!(captured[0].api_key, "ck_secret-key");
    assert_eq!(captured[0].api_version, "2026-07-31");
    assert_eq!(captured[0].content_type, "application/json");
    assert_eq!(captured[0].user_agent, USER_AGENT);
    assert!(captured[0].client_info.is_none());
    assert!(captured[0].idempotency_key.is_none());
    assert!(captured[0].body.is_empty());
    assert!(
        captured[1]
            .idempotency_key
            .as_deref()
            .unwrap()
            .starts_with("commet-node-retry-")
    );
    assert_eq!(captured[1].body, r#"{"value":1}"#);
    assert_eq!(captured[2].idempotency_key.as_deref(), Some("explicit-key"));
}

#[derive(Default)]
struct RetryState {
    attempts: AtomicUsize,
    keys: Mutex<Vec<Option<String>>>,
}

async fn retry_then_succeed(State(state): State<Arc<RetryState>>, request: Request) -> Response {
    state
        .keys
        .lock()
        .unwrap()
        .push(text_header(request.headers(), "idempotency-key"));
    if state.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "0.001")],
            axum::Json(json!({"error": {"message": "wait"}})),
        )
            .into_response();
    }
    axum::Json(json!({"retried": true})).into_response()
}

#[tokio::test]
async fn retries_429_only_with_positive_delay_and_reuses_one_generated_key() {
    let state = Arc::new(RetryState::default());
    let transport = CommetHttpTransport::new(
        CommetProviderConfig::with_base_url(
            "ck_key",
            server(
                Router::new()
                    .fallback(any(retry_then_succeed))
                    .with_state(state.clone()),
            )
            .await,
        )
        .unwrap(),
    );
    let response = transport
        .send(CommetTransportRequest::post("usage/events", json!({})))
        .await
        .unwrap();
    assert_eq!(response, json!({"retried": true}));
    assert_eq!(state.attempts.load(Ordering::SeqCst), 2);
    let keys = state.keys.lock().unwrap();
    assert_eq!(keys[0], keys[1]);
    assert!(
        keys[0]
            .as_deref()
            .unwrap()
            .starts_with("commet-node-retry-")
    );
}

async fn invalid_retry_response() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "not json").into_response()
}

#[tokio::test]
async fn parses_before_retrying_and_redacts_invalid_provider_json() {
    let transport = CommetHttpTransport::new(
        CommetProviderConfig::with_base_url(
            "ck_key",
            server(Router::new().fallback(any(invalid_retry_response))).await,
        )
        .unwrap(),
    );
    let error = transport
        .send(CommetTransportRequest::get("customers", Vec::new()))
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(500));
    assert_eq!(
        error.to_string(),
        "Invalid JSON response: 500 Internal Server Error"
    );
    assert!(!format!("{error:?}").contains("not json"));
}

#[tokio::test]
async fn retries_send_failures_after_a_connection_is_accepted() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let server_attempts = attempts.clone();
    tokio::spawn(async move {
        for _ in 0..2 {
            let (connection, _) = listener.accept().await.unwrap();
            server_attempts.fetch_add(1, Ordering::SeqCst);
            drop(connection);
        }
    });
    let transport = CommetHttpTransport::with_timeout_and_retries(
        CommetProviderConfig::with_base_url(
            "ck_key",
            Url::parse(&format!("http://{address}")).unwrap(),
        )
        .unwrap(),
        Duration::from_secs(2),
        1,
    )
    .unwrap();

    assert!(
        transport
            .send(CommetTransportRequest::get("customers", Vec::new()))
            .await
            .is_err()
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

async fn large_response() -> axum::Json<Value> {
    axum::Json(json!({"data": "x".repeat(2 * 1024 * 1024 + 1)}))
}

#[tokio::test]
async fn zero_timeout_configuration_and_unbounded_raw_json_match_the_sdk() {
    let config = CommetProviderConfig::new("ck_key").unwrap();
    assert!(CommetHttpTransport::with_timeout_and_retries(config, Duration::ZERO, 3).is_ok());
    let transport = CommetHttpTransport::with_timeout_and_retries(
        CommetProviderConfig::with_base_url(
            "ck_key",
            server(Router::new().fallback(any(large_response))).await,
        )
        .unwrap(),
        Duration::from_secs(1),
        0,
    )
    .unwrap();
    let response = transport
        .send(CommetTransportRequest::get("customers", Vec::new()))
        .await
        .unwrap();
    assert!(response["data"].as_str().unwrap().len() > 2 * 1024 * 1024);
}

#[test]
fn defaults_and_mutating_request_idempotency_match_sdk_9_1_0() {
    let transport = CommetHttpTransport::new(CommetProviderConfig::new("ck_key").unwrap());
    assert_eq!(transport.timeout, Duration::from_secs(30));
    assert_eq!(transport.max_retries, 3);
    assert_eq!(
        transport.idempotency_key(&CommetTransportRequest::get("path", Vec::new())),
        None
    );
    for request in [
        CommetTransportRequest::post("path", json!({})),
        CommetTransportRequest::put("path", json!({})),
        CommetTransportRequest::patch("path", json!({})),
    ] {
        assert!(
            transport
                .idempotency_key(&request)
                .unwrap()
                .starts_with("commet-node-retry-")
        );
    }

    let no_retries = CommetHttpTransport::with_timeout_and_retries(
        CommetProviderConfig::new("ck_key").unwrap(),
        Duration::from_secs(1),
        0,
    )
    .unwrap();
    assert_eq!(
        no_retries.idempotency_key(&CommetTransportRequest::post("path", json!({}))),
        None
    );
}
