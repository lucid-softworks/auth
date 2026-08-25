use crate::support::{FakePolarClient, fixture, selective_app, send};
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use base64::Engine;
use hmac::{Hmac, Mac};
use lucid_auth::{
    CheckoutOptions, PolarFeature, PolarOptions, PolarPlugin, PolarWebhookCallback,
    PolarWebhookCallbackError, PolarWebhookEvent, PortalOptions, UsageOptions, WebhooksOptions,
};
use serde_json::json;
use sha2::Sha256;
use std::sync::Arc;

const CUSTOMER_CREATED: &str = include_str!("fixtures/customer_created.json");

#[tokio::test]
async fn selective_registration_exposes_only_the_ten_official_method_path_pairs() {
    let empty = selective_app(Vec::new());
    assert_eq!(
        send(
            &empty,
            Request::post("/api/auth/checkout")
                .body(Body::from("{}"))
                .unwrap()
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    let app = selective_app(vec![
        PolarFeature::Checkout(CheckoutOptions::default()),
        PolarFeature::Portal(PortalOptions::default()),
        PolarFeature::Usage(UsageOptions::default()),
        PolarFeature::Webhooks(WebhooksOptions::new("secret")),
    ]);
    let routes = [
        (Method::POST, "/api/auth/checkout"),
        (Method::GET, "/api/auth/customer/portal"),
        (Method::POST, "/api/auth/customer/portal"),
        (Method::GET, "/api/auth/customer/state"),
        (Method::GET, "/api/auth/customer/benefits/list"),
        (Method::GET, "/api/auth/customer/subscriptions/list"),
        (Method::GET, "/api/auth/customer/orders/list"),
        (Method::GET, "/api/auth/usage/meters/list"),
        (Method::POST, "/api/auth/usage/ingest"),
        (Method::POST, "/api/auth/polar/webhooks"),
    ];
    for (method, path) in routes {
        let response = send(
            &app,
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
        assert_ne!(response.0, StatusCode::NOT_FOUND, "{path}");
        assert_ne!(response.0, StatusCode::METHOD_NOT_ALLOWED, "{path}");
    }
    for (method, path) in [
        (Method::GET, "/api/auth/checkout"),
        (Method::PUT, "/api/auth/customer/portal"),
        (Method::POST, "/api/auth/customer/state"),
        (Method::POST, "/api/auth/customer/benefits/list"),
        (Method::POST, "/api/auth/customer/subscriptions/list"),
        (Method::POST, "/api/auth/customer/orders/list"),
        (Method::POST, "/api/auth/usage/meters/list"),
        (Method::GET, "/api/auth/usage/ingest"),
        (Method::GET, "/api/auth/polar/webhooks"),
    ] {
        let response = send(
            &app,
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.0, StatusCode::METHOD_NOT_ALLOWED, "{path}");
    }
}

#[tokio::test]
async fn webhook_preserves_raw_text_and_maps_verification_failures() {
    let fixture = fixture().await;
    let body = CUSTOMER_CREATED;
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let valid_signature = signature("evt_contract", &timestamp, body, "whsec_contract");
    let accepted = send(
        &fixture.app,
        Request::post("/api/auth/polar/webhooks")
            .header("webhook-id", "evt_contract")
            .header("webhook-timestamp", &timestamp)
            .header(
                "webhook-signature",
                format!("v2,bogus v1,{valid_signature}"),
            )
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(accepted.0, StatusCode::OK);
    assert_eq!(accepted.2, json!({ "received": true }));

    let invalid = send(
        &fixture.app,
        Request::post("/api/auth/polar/webhooks")
            .header("webhook-id", "evt_contract")
            .header("webhook-timestamp", timestamp)
            .header("webhook-signature", "v1,invalid")
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(invalid.0, StatusCode::BAD_REQUEST);
    assert!(
        invalid.2["message"]
            .as_str()
            .unwrap()
            .starts_with("Webhook Error: ")
    );

    let unsupported_body = r#"{"type":"future.event","data":{}}"#;
    let unsupported_timestamp = chrono::Utc::now().timestamp().to_string();
    let unsupported_signature = signature(
        "evt_unsupported",
        &unsupported_timestamp,
        unsupported_body,
        "whsec_contract",
    );
    let unsupported = send(
        &fixture.app,
        Request::post("/api/auth/polar/webhooks")
            .header("webhook-id", "evt_unsupported")
            .header("webhook-timestamp", unsupported_timestamp)
            .header("webhook-signature", format!("v1,{unsupported_signature}"))
            .body(Body::from(unsupported_body))
            .unwrap(),
    )
    .await;
    assert_eq!(unsupported.0, StatusCode::BAD_REQUEST);
    assert!(
        unsupported.2["message"]
            .as_str()
            .unwrap()
            .starts_with("Webhook Error: ")
    );

    let absent = send(
        &fixture.app,
        Request::post("/api/auth/polar/webhooks")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(absent.0, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn webhook_empty_secret_and_callback_failure_keep_exact_messages() {
    let empty_secret = selective_app(vec![PolarFeature::Webhooks(WebhooksOptions::new(""))]);
    let missing_secret = send(
        &empty_secret,
        Request::post("/api/auth/polar/webhooks")
            .header(header::CONTENT_LENGTH, "2")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await;
    assert_eq!(missing_secret.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        missing_secret.2["message"],
        "Webhook Error: Polar webhook secret not found"
    );

    let mut webhooks = WebhooksOptions::new("callback_secret");
    webhooks.callbacks.on_payload = Some(Arc::new(FailingCallback));
    let client = Arc::new(FakePolarClient::default());
    let mut config = lucid_auth::AuthConfig::new([176_u8; 32]).unwrap();
    config
        .add_plugin(PolarPlugin::new(PolarOptions::new(
            client,
            vec![PolarFeature::Webhooks(webhooks)],
        )))
        .unwrap();
    let service = Arc::new(
        lucid_auth::AuthService::try_new(Arc::new(lucid_auth::MemoryStore::default()), config)
            .unwrap(),
    );
    let app = lucid_auth::axum::router(service);
    let body = CUSTOMER_CREATED;
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let response = send(
        &app,
        Request::post("/api/auth/polar/webhooks")
            .header("webhook-id", "evt_callback")
            .header("webhook-timestamp", &timestamp)
            .header(
                "webhook-signature",
                format!(
                    "v1,{}",
                    signature("evt_callback", &timestamp, body, "callback_secret")
                ),
            )
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(response.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        response.2["message"],
        "Webhook error: See server logs for more information."
    );
}

fn signature(id: &str, timestamp: &str, body: &str, secret: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{id}.{timestamp}.{body}").as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

struct FailingCallback;

#[async_trait]
impl PolarWebhookCallback for FailingCallback {
    async fn call(&self, _event: &PolarWebhookEvent) -> Result<(), PolarWebhookCallbackError> {
        Err(PolarWebhookCallbackError::new("callback failed"))
    }
}
