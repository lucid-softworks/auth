use axum::{
    Router,
    body::{Body, Bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use lucid_auth::{
    AuthConfig, AuthService, DodoPaymentsFeature, DodoPaymentsHttpClient, DodoPaymentsOptions,
    DodoPaymentsPlugin, DodoPaymentsProviderConfig, DodoWebhookCallbacks, DodoWebhooksOptions,
    MemoryStore,
};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

pub(crate) const WEBHOOK_PATH: &str = "/api/auth/dodopayments/webhooks";
const RAW_SECRET: &[u8] = b"Dodo webhook route contract secret";

pub(crate) struct TestResponse {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Bytes,
}

impl TestResponse {
    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("webhook response is JSON")
    }
}

pub(crate) fn webhook_secret() -> String {
    format!("whsec_{}", STANDARD.encode(RAW_SECRET))
}

pub(crate) fn app(secret: &str, callbacks: DodoWebhookCallbacks) -> Router {
    let client = Arc::new(DodoPaymentsHttpClient::new(
        DodoPaymentsProviderConfig::test("unused-webhook-contract-key"),
    ));
    let store = Arc::new(MemoryStore::default());
    let mut webhooks = DodoWebhooksOptions::new(secret);
    webhooks.callbacks = callbacks;
    let plugin = DodoPaymentsPlugin::new(
        DodoPaymentsOptions::new(client, vec![DodoPaymentsFeature::Webhooks(webhooks)]),
        store.clone(),
    );
    let mut config = AuthConfig::new([209_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config.add_plugin(plugin).unwrap();
    let service = Arc::new(AuthService::try_new(store, config).unwrap());
    lucid_auth::axum::router(service)
}

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub(crate) fn known_body() -> String {
    json!({
        "business_id": "biz_contract",
        "type": "dunning.started",
        "timestamp": "2026-08-25T12:00:00.000Z",
        "data": {
            "payload_type": "DunningAttempt",
            "brand_id": "brand_contract",
            "created_at": "2026-08-25T12:00:00.000Z",
            "customer_id": "cus_contract",
            "status": "recovering",
            "subscription_id": "sub_contract",
            "trigger_state": "on_hold"
        }
    })
    .to_string()
}

pub(crate) fn unknown_body() -> String {
    json!({
        "business_id": "biz_contract",
        "type": "future.event",
        "timestamp": "2026-08-25T12:00:00.000Z",
        "data": {"future": [true, 7, null]}
    })
    .to_string()
}

pub(crate) async fn signed_post(
    app: &Router,
    id: &str,
    timestamp: i64,
    body: &str,
    secret: &str,
) -> TestResponse {
    let signature = signature(body, id, timestamp, secret);
    post(
        app,
        Some(body),
        &[
            ("webhook-id", id.to_owned()),
            ("webhook-timestamp", timestamp.to_string()),
            ("webhook-signature", signature),
        ],
    )
    .await
}

pub(crate) async fn post(
    app: &Router,
    body: Option<&str>,
    headers: &[(&'static str, String)],
) -> TestResponse {
    let mut request = Request::post(WEBHOOK_PATH);
    let body = match body {
        Some(body) => {
            request = request
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_LENGTH, body.len().to_string());
            Body::from(body.to_owned())
        }
        None => Body::empty(),
    };
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    send(app, request.body(body).unwrap()).await
}

fn signature(body: &str, id: &str, timestamp: i64, secret: &str) -> String {
    let encoded = secret.strip_prefix("whsec_").unwrap_or(secret);
    let key = STANDARD.decode(encoded).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(format!("{id}.{timestamp}.{body}").as_bytes());
    format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes()))
}

async fn send(app: &Router, request: Request<Body>) -> TestResponse {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    TestResponse {
        status,
        headers,
        body,
    }
}
