use super::*;
use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::json;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokio::net::TcpListener;

#[derive(Default)]
struct RetryState {
    attempts: AtomicUsize,
    request_headers: Mutex<Vec<(String, String)>>,
}

async fn retry_then_succeed(State(state): State<Arc<RetryState>>, request: Request) -> Response {
    state.request_headers.lock().unwrap().push((
        header(request.headers(), "x-stainless-retry-count").unwrap(),
        header(request.headers(), "x-stainless-timeout").unwrap(),
    ));
    match state.attempts.fetch_add(1, Ordering::SeqCst) {
        0 => (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after-ms", "0")],
            "rate limited",
        )
            .into_response(),
        1 => (
            StatusCode::SERVICE_UNAVAILABLE,
            [("retry-after-ms", "0")],
            "unavailable",
        )
            .into_response(),
        _ => axum::Json(json!({"items": []})).into_response(),
    }
}

#[tokio::test]
async fn retries_twice_and_increments_stainless_headers() {
    let state = Arc::new(RetryState::default());
    let base_url = server(
        Router::new()
            .route("/api/events", get(retry_then_succeed))
            .with_state(state.clone()),
    )
    .await;
    let transport = DodoPaymentsHttpTransport::new(DodoPaymentsProviderConfig::with_base_url(
        "key",
        DodoPaymentsEnvironment::Test,
        base_url,
    ));
    let response = transport
        .send(DodoPaymentsTransportRequest::get("events", Vec::new()))
        .await
        .unwrap();

    assert_eq!(response, json!({"items": []}));
    assert_eq!(state.attempts.load(Ordering::SeqCst), 3);
    assert_eq!(
        *state.request_headers.lock().unwrap(),
        [
            ("0".into(), "60".into()),
            ("1".into(), "60".into()),
            ("2".into(), "60".into())
        ]
    );
}

async fn override_retry(State(state): State<Arc<RetryState>>, request: Request) -> Response {
    let attempt = state.attempts.fetch_add(1, Ordering::SeqCst);
    match request.uri().path() {
        "/api/disabled" => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("x-should-retry", "false")],
            "stop",
        )
            .into_response(),
        _ if attempt == 0 => (
            StatusCode::BAD_REQUEST,
            [("x-should-retry", "true"), ("retry-after-ms", "0")],
            "retry",
        )
            .into_response(),
        _ => axum::Json(json!({"ok": true})).into_response(),
    }
}

#[tokio::test]
async fn x_should_retry_overrides_status_defaults() {
    let disabled = Arc::new(RetryState::default());
    let base_url = server(
        Router::new()
            .fallback(get(override_retry))
            .with_state(disabled.clone()),
    )
    .await;
    let transport = DodoPaymentsHttpTransport::new(DodoPaymentsProviderConfig::with_base_url(
        "key",
        DodoPaymentsEnvironment::Test,
        base_url.clone(),
    ));
    let error = transport
        .send(DodoPaymentsTransportRequest::get("disabled", Vec::new()))
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(500));
    assert_eq!(disabled.attempts.load(Ordering::SeqCst), 1);

    let enabled = Arc::new(RetryState::default());
    let transport = DodoPaymentsHttpTransport::new(DodoPaymentsProviderConfig::with_base_url(
        "key",
        DodoPaymentsEnvironment::Test,
        server(
            Router::new()
                .fallback(get(override_retry))
                .with_state(enabled.clone()),
        )
        .await,
    ));
    assert_eq!(
        transport
            .send(DodoPaymentsTransportRequest::get("enabled", Vec::new()))
            .await
            .unwrap(),
        json!({"ok": true})
    );
    assert_eq!(enabled.attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn retries_connection_failures_up_to_the_default_maximum() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let server_accepted = accepted.clone();
    tokio::spawn(async move {
        for _ in 0..3 {
            let (connection, _) = listener.accept().await.unwrap();
            server_accepted.fetch_add(1, Ordering::SeqCst);
            drop(connection);
        }
    });
    let transport = DodoPaymentsHttpTransport::new(DodoPaymentsProviderConfig::with_base_url(
        "key",
        DodoPaymentsEnvironment::Test,
        url::Url::parse(&format!("http://{address}/")).unwrap(),
    ));
    let error = transport
        .send(DodoPaymentsTransportRequest::get("events", Vec::new()))
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "Dodo Payments HTTP request failed");
    assert_eq!(accepted.load(Ordering::SeqCst), 3);
}

async fn time_out(State(attempts): State<Arc<AtomicUsize>>) -> axum::Json<Value> {
    attempts.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(100)).await;
    axum::Json(json!({"late": true}))
}

#[tokio::test]
async fn retries_timeouts_and_reports_the_final_timeout() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let base_url = server(
        Router::new()
            .route("/api/events", get(time_out))
            .with_state(attempts.clone()),
    )
    .await;
    let transport = DodoPaymentsHttpTransport::with_limits(
        DodoPaymentsProviderConfig::with_base_url("key", DodoPaymentsEnvironment::Test, base_url),
        Duration::from_millis(10),
        1_024,
    )
    .unwrap();
    let error = transport
        .send(DodoPaymentsTransportRequest::get("events", Vec::new()))
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "Dodo Payments HTTP request timed out");
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}
