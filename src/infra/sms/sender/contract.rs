use super::*;
use crate::infra::sms::{SmsApiOptions, SmsTemplateId};
use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use serde_json::{Value, json};
use tokio::sync::mpsc;

struct RecordedRequest {
    headers: HeaderMap,
    body: Value,
}

async fn record_send(
    State(sender): State<mpsc::UnboundedSender<RecordedRequest>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    sender.send(RecordedRequest { headers, body }).unwrap();
    Json(json!({ "providerIgnored": true, "messageId": 42 }))
}

async fn server() -> (
    String,
    mpsc::UnboundedReceiver<RecordedRequest>,
    tokio::task::JoinHandle<()>,
) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let app = Router::new()
        .route("/api/v1/sms/send", post(record_send))
        .route("/v1/sms/send", post(record_send))
        .with_state(sender);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), receiver, task)
}

fn config(api_url: String) -> SmsConfig {
    SmsConfig {
        api_key: Some("managed-key".into()),
        api_url: Some(api_url),
        api_options: Some(SmsApiOptions {
            timeout: Some(1_000),
        }),
        ..SmsConfig::default()
    }
}

#[tokio::test]
async fn send_uses_exact_headers_body_and_unvalidated_message_id() {
    let (api_url, mut requests, server) = server().await;
    let sender = SmsSender::new(Some(config(api_url)));

    let result = sender
        .send(
            SendSmsOptions::new("not-e164", "123456")
                .with_template(SmsTemplateId::PhoneVerification)
                .with_client_ip("203.0.113.8"),
        )
        .await;
    let request = requests.recv().await.unwrap();

    assert!(result.success);
    assert_eq!(result.message_id, Some(json!(42)));
    assert_eq!(request.headers[header::AUTHORIZATION], "Bearer managed-key");
    assert_eq!(request.headers[header::USER_AGENT], USER_AGENT);
    assert_eq!(request.headers[CLIENT_IP_HEADER], "203.0.113.8");
    assert_eq!(
        request.body,
        json!({
            "to": "not-e164",
            "code": "123456",
            "template": "phone-verification"
        })
    );
    assert!(requests.try_recv().is_err());
    server.abort();
}

#[tokio::test]
async fn generic_send_omits_template_and_falsey_client_ip_header() {
    let (api_url, mut requests, server) = server().await;
    let sender = SmsSender::new(Some(config(api_url)));

    let result = sender
        .send(SendSmsOptions::new("", "").with_client_ip(""))
        .await;
    let request = requests.recv().await.unwrap();

    assert!(result.success);
    assert_eq!(request.body, json!({ "to": "", "code": "" }));
    assert!(!request.headers.contains_key(CLIENT_IP_HEADER));
    server.abort();
}

#[tokio::test]
async fn every_template_uses_one_unvalidated_request() {
    let (api_url, mut requests, server) = server().await;
    let sender = SmsSender::new(Some(config(api_url)));

    for template in [
        SmsTemplateId::PhoneVerification,
        SmsTemplateId::TwoFactor,
        SmsTemplateId::SignInOtp,
    ] {
        assert!(
            sender
                .send(SendSmsOptions::new("anything", "code").with_template(template))
                .await
                .success
        );
    }

    for _ in 0..3 {
        requests.recv().await.unwrap();
    }
    assert!(requests.try_recv().is_err());
    server.abort();
}

#[tokio::test]
async fn missing_key_short_circuits_and_sender_debug_is_redacted() {
    let sender = SmsSender::new(Some(SmsConfig {
        api_key: Some(String::new()),
        api_url: Some("http://127.0.0.1:1".into()),
        ..SmsConfig::default()
    }));
    let result = sender
        .send(SendSmsOptions::new("private-phone", "secret-code"))
        .await;

    assert_eq!(result.error, Some(json!("API key not configured")));
    let debug = format!("{sender:?}");
    assert!(!debug.contains("127.0.0.1"));
    assert!(!debug.contains("private-phone"));
    assert!(!debug.contains("secret-code"));
}

#[tokio::test]
async fn query_and_fragment_base_urls_resolve_operation_from_the_origin_root() {
    for suffix in [
        "/base?foo=1",
        "/base#fragment",
        "/api?foo=1",
        "/api#fragment",
    ] {
        let (origin, mut requests, server) = server().await;
        let sender = SmsSender::new(Some(config(format!("{origin}{suffix}"))));

        assert!(
            sender
                .send(SendSmsOptions::new("person", "code"))
                .await
                .success
        );
        requests.recv().await.unwrap();
        server.abort();
    }
}

#[tokio::test]
async fn one_shot_wrapper_uses_the_same_request_contract() {
    let (api_url, mut requests, server) = server().await;

    let result = send_sms(
        SendSmsOptions::new("person", "code").with_template(SmsTemplateId::TwoFactor),
        Some(config(api_url)),
    )
    .await;

    assert!(result.success);
    assert_eq!(
        requests.recv().await.unwrap().body,
        json!({ "to": "person", "code": "code", "template": "two-factor" })
    );
    assert!(requests.try_recv().is_err());
    server.abort();
}
