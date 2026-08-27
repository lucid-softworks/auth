use super::*;
use crate::infra::dash::{InfraConnectionOptions, KvOptions, KvRetryOptions};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap as AxumHeaders, StatusCode},
    response::IntoResponse,
    routing::get,
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

async fn identify(
    State(calls): State<Arc<AtomicUsize>>,
    Path(request_id): Path<String>,
) -> impl IntoResponse {
    calls.fetch_add(1, Ordering::SeqCst);
    if request_id == "missing" {
        return (StatusCode::NOT_FOUND, Json(json!({ "message": "missing" })));
    }
    if request_id == "failure" {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "message": "failed" })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "visitorId": "bound-visitor",
            "requestId": request_id,
            "timestamp": 1,
            "url": "https://app.test/sign-in",
            "ip": "203.0.113.8",
            "location": {
                "lat": 1,
                "lng": 2,
                "city": "London",
                "region": null,
                "postalCode": null,
                "country": { "code": "gb", "name": "United Kingdom" },
                "timezone": null
            },
            "browser": {},
            "confidence": 0.9,
            "incognito": false,
            "bot": "notDetected"
        })),
    )
}

async fn fixture() -> (
    IdentificationService,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/identify/{request_id}", get(identify))
        .with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let options = InfraConnectionOptions {
        kv_url: Some(format!("http://{address}")),
        kv_options: Some(KvOptions {
            retry: Some(KvRetryOptions {
                attempts: Some(2),
                base_delay: Some(0),
                max_delay: Some(0),
            }),
            ..KvOptions::default()
        }),
        ..InfraConnectionOptions::default()
    }
    .resolve();
    (IdentificationService::new(&options), calls, server)
}

fn request(path: &str) -> IdentificationRequest {
    IdentificationRequest {
        method: Method::POST,
        path: path.into(),
        headers: AxumHeaders::new(),
        request_id_cookie: None,
        ip_options: IdentificationIpOptions::default(),
    }
}

#[tokio::test]
async fn binds_only_the_identified_visitor_and_derives_location() {
    let (service, calls, server) = fixture().await;
    let mut request = request("/sign-in/email");
    request
        .headers
        .insert("x-request-id", "bound-request".parse().unwrap());
    request
        .headers
        .insert("x-visitor-id", "spoofed-visitor".parse().unwrap());
    let context = service.identify(&request).await;

    assert_eq!(context.request_id.as_deref(), Some("bound-request"));
    assert_eq!(context.visitor_id.as_deref(), Some("bound-visitor"));
    assert_eq!(context.ip.as_deref(), Some("203.0.113.8"));
    assert_eq!(
        context.untrusted_visitor_id.as_deref(),
        Some("bound-visitor")
    );
    assert_eq!(
        context.location,
        Some(IdentificationLocation {
            ip_address: Some("203.0.113.8".into()),
            city: Some("London".into()),
            country: Some("United Kingdom".into()),
            country_code: Some("gb".into()),
        })
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        IdentificationService::cookie_after(&request, &context),
        Some(IdentificationCookie::Set {
            name: "__infra-rid",
            value: "bound-request".into(),
            max_age_seconds: 600,
            http_only: true,
            same_site: "lax",
            path: "/",
        })
    );
    server.abort();
}

#[tokio::test]
async fn fresh_cache_hits_do_not_repeat_kv_requests() {
    let (service, calls, server) = fixture().await;
    let mut request = request("/verify-email");
    request
        .headers
        .insert("x-request-id", "cached-request".parse().unwrap());
    service.identify(&request).await;
    service.identify(&request).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn missing_records_retry_but_service_failures_cache_null() {
    let (service, calls, server) = fixture().await;
    let mut missing = request("/verify-email");
    missing
        .headers
        .insert("x-request-id", "missing".parse().unwrap());
    assert!(service.identify(&missing).await.identification.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert!(service.identify(&missing).await.identification.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 6);

    let mut failure = request("/verify-email");
    failure
        .headers
        .insert("x-request-id", "failure".parse().unwrap());
    assert!(service.identify(&failure).await.identification.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 7);
    assert!(service.identify(&failure).await.identification.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 7);
    server.abort();
}

#[tokio::test]
async fn dash_paths_skip_identity_but_keep_request_ip_fallback() {
    let (service, calls, server) = fixture().await;
    let mut request = request("/dash/users");
    request
        .headers
        .insert("x-request-id", "ignored".parse().unwrap());
    request.headers.insert(
        "cf-connecting-ip",
        "198.51.100.7, 10.0.0.1".parse().unwrap(),
    );
    request
        .headers
        .insert("cf-ipcountry", "us".parse().unwrap());
    let context = service.identify(&request).await;
    assert!(context.request_id.is_none());
    assert!(context.identification.is_none());
    assert_eq!(context.ip.as_deref(), Some("198.51.100.7"));
    assert_eq!(
        context.untrusted_visitor_id.as_deref(),
        Some("ip:198.51.100.7")
    );
    assert_eq!(
        context.location.unwrap().country_code.as_deref(),
        Some("US")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn present_empty_headers_block_cookie_fallback_like_nullish_coalescing() {
    let (service, calls, server) = fixture().await;
    let mut request = request("/callback/github");
    request.method = Method::GET;
    request.request_id_cookie = Some("cookie-request".into());
    request.headers.insert("x-request-id", "".parse().unwrap());
    request.headers.insert("x-visitor-id", "".parse().unwrap());
    let context = service.identify(&request).await;

    assert_eq!(context.request_id.as_deref(), Some(""));
    assert_eq!(context.untrusted_visitor_id.as_deref(), Some(""));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        IdentificationService::cookie_after(&request, &context),
        None
    );
    server.abort();
}

#[test]
fn callback_cookie_is_cleared_after_cookie_based_resolution() {
    let mut request = request("/callback/github");
    request.method = Method::GET;
    request.request_id_cookie = Some("redirect-request".into());
    let context = IdentificationContext {
        request_id: Some("redirect-request".into()),
        ..IdentificationContext::default()
    };
    assert_eq!(
        IdentificationService::cookie_after(&request, &context),
        Some(IdentificationCookie::Clear {
            name: "__infra-rid",
            max_age_seconds: 0,
            path: "/",
        })
    );
}
