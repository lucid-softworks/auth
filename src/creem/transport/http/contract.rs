use super::*;
use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode as AxumStatus},
    response::{IntoResponse, Response},
    routing::any,
};
use std::sync::{Arc, Mutex};

const CHECKOUT_RESPONSE: &str = r#"{"id":"checkout_1","mode":"test","object":"checkout","status":"pending","product":"product_1"}"#;
const PORTAL_RESPONSE: &str = r#"{"customer_portal_link":"https://portal.test/1"}"#;
const TRANSACTION_RESPONSE: &str = r#"{"items":[],"pagination":{"total_records":0,"total_pages":1,"current_page":1,"next_page":null,"prev_page":null}}"#;
const SUBSCRIPTION_RESPONSE: &str = r#"{"id":"subscription_1","mode":"test","object":"subscription","product":"product_1","customer":"customer_1","collection_method":"charge_automatically","status":"active","created_at":"2026-07-01T00:00:00Z","updated_at":"2026-08-01T00:00:00Z"}"#;

#[derive(Debug)]
struct CapturedRequest {
    method: Method,
    path: String,
    query: Option<String>,
    api_key: Option<String>,
    body: Value,
}

#[derive(Clone)]
struct FixtureState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    response: Option<(AxumStatus, HeaderMap, String)>,
}

async fn capture(State(state): State<FixtureState>, request: Request) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().map(str::to_owned);
    let api_key = request
        .headers()
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = to_bytes(request.into_body(), 1024 * 1024)
        .await
        .ok()
        .filter(|body| !body.is_empty())
        .and_then(|body| serde_json::from_slice(&body).ok())
        .unwrap_or(Value::Null);
    state.requests.lock().unwrap().push(CapturedRequest {
        method,
        path: path.clone(),
        query,
        api_key,
        body,
    });
    if let Some((status, headers, body)) = state.response {
        return (status, headers, body).into_response();
    }
    (
        AxumStatus::OK,
        [(header::CONTENT_TYPE.as_str(), "application/json")],
        response_for(&path),
    )
        .into_response()
}

fn response_for(path: &str) -> &'static str {
    match path {
        "/base/v1/checkouts" => CHECKOUT_RESPONSE,
        "/base/v1/customers/billing" => PORTAL_RESPONSE,
        "/base/v1/transactions/search" => TRANSACTION_RESPONSE,
        _ => SUBSCRIPTION_RESPONSE,
    }
}

async fn fixture_client(
    response: Option<(AxumStatus, HeaderMap, String)>,
    limit: usize,
) -> (CreemHttpTransport, Arc<Mutex<Vec<CapturedRequest>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = FixtureState {
        requests: requests.clone(),
        response,
    };
    let app = Router::new().fallback(any(capture)).with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let config = CreemProviderConfig::with_base_url(
        "  secret key\t",
        Url::parse(&format!("http://{address}/base")).unwrap(),
    );
    let client = CreemHttpTransport::with_limits(config, Duration::from_secs(2), limit).unwrap();
    (client, requests)
}

fn checkout_request() -> CreemCheckoutRequest {
    CreemCheckoutRequest {
        request_id: Some("request 1".into()),
        product_id: "product_1".into(),
        units: None,
        discount_code: None,
        customer: None,
        custom_fields: None,
        success_url: None,
        metadata: None,
    }
}

#[test]
fn encode_component_matches_javascript_encode_uri_component() {
    assert_eq!(encode_component("a/b ?!'()*~"), "a%2Fb%20%3F!'()*~");
}

#[tokio::test]
async fn sends_the_exact_five_sdk_requests_and_preserves_base_paths() {
    let (client, requests) = fixture_client(None, DEFAULT_RESPONSE_LIMIT).await;
    let checkout = client.create_checkout(checkout_request()).await.unwrap();
    assert_eq!(checkout.checkout_url, None);
    client
        .create_portal(CreemPortalRequest {
            customer_id: "customer_1".into(),
        })
        .await
        .unwrap();
    client.cancel_subscription("a/b ?").await.unwrap();
    client.retrieve_subscription("sub id&x").await.unwrap();
    client
        .search_transactions(CreemTransactionSearch {
            customer_id: Some("customer 1".into()),
            order_id: Some("order&1".into()),
            product_id: Some("product/1".into()),
            page_number: None,
            page_size: None,
        })
        .await
        .unwrap();

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert_eq!(requests[0].method, Method::POST);
    assert_eq!(requests[0].path, "/base/v1/checkouts");
    assert_eq!(requests[0].api_key.as_deref(), Some("secret key"));
    assert_eq!(
        requests[0].body,
        json!({"request_id":"request 1","product_id":"product_1"})
    );
    assert_eq!(requests[1].path, "/base/v1/customers/billing");
    assert_eq!(requests[1].body, json!({"customer_id":"customer_1"}));
    assert_eq!(
        requests[2].path,
        "/base/v1/subscriptions/a%2Fb%20%3F/cancel"
    );
    assert_eq!(requests[2].body, json!({}));
    assert_eq!(requests[3].method, Method::GET);
    assert_eq!(requests[3].path, "/base/v1/subscriptions");
    assert_eq!(
        requests[3].query.as_deref(),
        Some("subscription_id=sub%20id%26x")
    );
    assert_eq!(requests[4].path, "/base/v1/transactions/search");
    assert_eq!(
        requests[4].query.as_deref(),
        Some(
            "customer_id=customer%201&order_id=order%261&page_number=1&page_size=10&product_id=product%2F1"
        )
    );
}

#[tokio::test]
async fn makes_one_request_without_retries_and_uses_sdk_status_errors() {
    let response = Some((
        AxumStatus::INTERNAL_SERVER_ERROR,
        HeaderMap::new(),
        "provider secret".into(),
    ));
    let (client, requests) = fixture_client(response, DEFAULT_RESPONSE_LIMIT).await;
    let error = client
        .create_checkout(checkout_request())
        .await
        .unwrap_err();
    assert_eq!(error.status, Some(500));
    assert_eq!(error.message, "API error occurred");
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert!(!format!("{error:?}").contains("provider secret"));
}

#[tokio::test]
async fn requires_http_200_json_and_bounds_response_bodies() {
    let response = Some((AxumStatus::OK, HeaderMap::new(), "{}".into()));
    let (client, _) = fixture_client(response, DEFAULT_RESPONSE_LIMIT).await;
    let error = client
        .create_checkout(checkout_request())
        .await
        .unwrap_err();
    assert_eq!(error.message, "Unexpected Status or Content-Type");

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    let response = Some((AxumStatus::OK, headers, "0123456789".into()));
    let (client, _) = fixture_client(response, 4).await;
    let error = client
        .create_checkout(checkout_request())
        .await
        .unwrap_err();
    assert_eq!(error.message, "Unexpected HTTP client error");
}

#[tokio::test]
async fn omits_an_empty_api_key_header_and_rejects_non_finite_inputs() {
    let (mut client, requests) = fixture_client(None, DEFAULT_RESPONSE_LIMIT).await;
    client.config.api_key = Arc::from("");
    client.create_checkout(checkout_request()).await.unwrap();
    assert_eq!(requests.lock().unwrap()[0].api_key, None);

    let error = client
        .search_transactions(CreemTransactionSearch {
            page_number: Some(f64::NAN),
            ..CreemTransactionSearch::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.message, "Input validation failed");
    assert_eq!(requests.lock().unwrap().len(), 1);
}
