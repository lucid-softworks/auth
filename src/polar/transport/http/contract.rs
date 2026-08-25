use super::*;
use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::header,
    response::{IntoResponse, Response},
    routing::any,
};
use serde_json::json;
use std::sync::Mutex;

const CHECKOUT_RESPONSE: &str = r#"{"id":"checkout_1","created_at":"2025-01-01T00:00:00Z","modified_at":null,"payment_processor":"stripe","status":"open","client_secret":"secret","url":"https://polar.sh/checkout/1","expires_at":"2025-01-01T00:00:00Z","success_url":"https://app.test/success","return_url":null,"embed_origin":null,"amount":0,"discount_amount":0,"net_amount":0,"tax_amount":null,"tax_behavior":null,"total_amount":0,"currency":"usd","allow_trial":null,"active_trial_interval":null,"active_trial_interval_count":null,"trial_end":null,"organization_id":"org_1","product_id":null,"product_price_id":null,"discount_id":null,"allow_discount_codes":false,"require_billing_address":false,"is_discount_applicable":false,"is_free_product_price":false,"is_payment_required":false,"is_payment_setup_required":false,"is_payment_form_required":false,"customer_id":null,"is_business_customer":false,"customer_name":null,"customer_email":null,"customer_ip_address":null,"customer_billing_name":null,"customer_billing_address":null,"customer_tax_id":null,"payment_processor_metadata":{},"billing_address_fields":{"country":"required","state":"required","city":"required","postal_code":"required","line1":"required","line2":"required"},"trial_interval":null,"trial_interval_count":null,"metadata":{},"external_customer_id":null,"products":[],"product":null,"product_price":null,"prices":null,"discount":null,"subscription_id":null,"attached_custom_fields":null,"customer_metadata":{}}"#;
const PAGE_RESPONSE: &str = r#"{"items":[],"pagination":{"total_count":0,"max_page":1}}"#;

#[derive(Debug)]
struct CapturedRequest {
    method: Method,
    path: String,
    query: Option<String>,
    authorization: Option<String>,
    body: Value,
}

async fn capture(
    State(requests): State<Arc<Mutex<Vec<CapturedRequest>>>>,
    request: Request,
) -> Response {
    let captured = captured_request(request).await;
    let path = captured.path.clone();
    requests.lock().unwrap().push(captured);
    response_for(&path)
}

async fn captured_request(request: Request) -> CapturedRequest {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().map(str::to_owned);
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = to_bytes(request.into_body(), 1024 * 1024)
        .await
        .ok()
        .filter(|body| !body.is_empty())
        .and_then(|body| serde_json::from_slice(&body).ok())
        .unwrap_or(Value::Null);
    CapturedRequest {
        method,
        path,
        query,
        authorization,
        body,
    }
}

fn response_for(path: &str) -> Response {
    let (status, body) = response_body(path);
    (status, [json_content_type()], body).into_response()
}

fn response_body(path: &str) -> (StatusCode, &'static str) {
    if path == "/v1/checkouts/" {
        (StatusCode::CREATED, CHECKOUT_RESPONSE)
    } else {
        (StatusCode::OK, PAGE_RESPONSE)
    }
}

fn json_content_type() -> (&'static str, &'static str) {
    ("content-type", "application/json")
}

async fn mock_client() -> (PolarHttpClient, Arc<Mutex<Vec<CapturedRequest>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .fallback(any(capture))
        .with_state(requests.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = PolarHttpClient::new("organization-token")
        .with_api_base(Url::parse(&format!("http://{address}/")).unwrap());
    (client, requests)
}

#[test]
fn redacts_tokens_and_supports_all_api_bases() {
    let production = PolarHttpClient::new("polar_secret");
    assert_eq!(production.api_base.as_str(), "https://api.polar.sh/");
    assert!(!format!("{production:?}").contains("polar_secret"));
    assert_eq!(
        PolarHttpClient::sandbox("secret").api_base.as_str(),
        "https://sandbox-api.polar.sh/"
    );
    let custom = production.with_api_base(Url::parse("http://localhost:1234/api").unwrap());
    assert_eq!(
        custom.url("v1/checkouts/").unwrap().as_str(),
        "http://localhost:1234/api/v1/checkouts/"
    );
}

#[test]
fn default_list_queries_match_the_sdk_defaults_and_reference_is_deep_object() {
    assert_eq!(
        outbound_query(&PolarPageQuery::default(), OutboundKind::BenefitGrantsList),
        Ok(vec![
            ("page".into(), "1".into()),
            ("limit".into(), "10".into())
        ])
    );
    assert_eq!(path_segment("a/b"), "a%2Fb");
}

#[tokio::test]
async fn rejects_non_integer_sdk_page_values_before_network_io() {
    let (client, requests) = mock_client().await;
    let error = client
        .list_benefits(
            "customer-session",
            PolarPageQuery {
                page: Some(1.5),
                limit: Some(10.0),
            },
        )
        .await
        .unwrap_err();
    assert!(error.message.contains("SDK request validation"));
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn sends_exact_organization_and_customer_session_request_shapes() {
    let (client, requests) = mock_client().await;
    let checkout = client
        .create_checkout(PolarCheckoutCreate {
            external_customer_id: Some("user-1".into()),
            products: vec!["product-1".into()],
            success_url: Some("https://app.test/success".into()),
            return_url: None,
            metadata: None,
            custom_field_data: None,
            allow_discount_codes: true,
            discount_id: None,
            embed_origin: None,
            allow_trial: None,
            trial_interval: None,
            trial_interval_count: None,
        })
        .await
        .unwrap();
    assert_eq!(checkout.url, "https://polar.sh/checkout/1");
    let page = client
        .list_benefits("customer-session", PolarPageQuery::default())
        .await
        .unwrap();
    assert_eq!(page["result"]["pagination"]["totalCount"], 0);

    let requests = requests.lock().unwrap();
    assert_eq!(requests[0].method, Method::POST);
    assert_eq!(requests[0].path, "/v1/checkouts/");
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer organization-token")
    );
    assert_eq!(requests[0].body["external_customer_id"], "user-1");
    assert_eq!(requests[0].body["allow_discount_codes"], true);
    assert_eq!(requests[1].method, Method::GET);
    assert_eq!(requests[1].path, "/v1/customer-portal/benefit-grants/");
    assert_eq!(requests[1].query.as_deref(), Some("page=1&limit=10"));
    assert_eq!(
        requests[1].authorization.as_deref(),
        Some("Bearer customer-session")
    );
}

#[test]
fn customer_creation_matches_the_sdk_default_individual_variant() {
    let value = serde_json::to_value(PolarCustomerCreate {
        email: "person@example.com".into(),
        name: Some("Person".into()),
        metadata: None,
    })
    .unwrap();
    assert_eq!(
        value,
        json!({"email":"person@example.com","name":"Person","type":"individual"})
    );
}
