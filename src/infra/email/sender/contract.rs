use super::*;
use crate::infra::email::{EmailApiOptions, ResetPasswordVariables, VerifyEmailVariables};
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use serde_json::json;
use tokio::sync::mpsc;

struct RecordedRequest {
    operation: &'static str,
    headers: HeaderMap,
    body: Option<Value>,
}

async fn record_send(
    State(sender): State<mpsc::UnboundedSender<RecordedRequest>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    sender
        .send(RecordedRequest {
            operation: "send",
            headers,
            body: Some(body),
        })
        .unwrap();
    Json(json!({ "providerIgnored": true, "messageId": 42 }))
}

async fn record_bulk(
    State(sender): State<mpsc::UnboundedSender<RecordedRequest>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    sender
        .send(RecordedRequest {
            operation: "bulk",
            headers,
            body: Some(body),
        })
        .unwrap();
    Json(json!({ "success": true, "failures": "unchecked" }))
}

async fn record_templates(
    State(sender): State<mpsc::UnboundedSender<RecordedRequest>>,
    headers: HeaderMap,
) -> Json<Value> {
    sender
        .send(RecordedRequest {
            operation: "templates",
            headers,
            body: None,
        })
        .unwrap();
    Json(json!([3, { "arbitrary": true }]))
}

async fn server() -> (
    String,
    mpsc::UnboundedReceiver<RecordedRequest>,
    tokio::task::JoinHandle<()>,
) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let app = Router::new()
        .route("/api/v1/email/send", post(record_send))
        .route("/api/v1/email/send-bulk", post(record_bulk))
        .route("/api/v1/email/templates", get(record_templates))
        .route("/v1/email/send", post(record_send))
        .with_state(sender);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), receiver, task)
}

fn config(api_url: String) -> EmailConfig {
    EmailConfig {
        api_key: Some("managed-key".into()),
        api_url: Some(api_url),
        api_options: Some(EmailApiOptions {
            timeout: Some(1_000),
        }),
        ..EmailConfig::default()
    }
}

#[tokio::test]
async fn send_uses_exact_headers_body_and_unvalidated_message_id() {
    let (api_url, mut requests, server) = server().await;
    let sender = EmailSender::new(Some(config(api_url)));
    let variables = ResetPasswordVariables::new("https://app.test/reset", "a@example.com");

    let result = sender
        .send(SendEmailOptions::new("a@example.com", variables).with_subject("Reset"))
        .await;
    let request = requests.recv().await.unwrap();

    assert!(result.success);
    assert_eq!(result.message_id, Some(json!(42)));
    assert_eq!(request.operation, "send");
    assert_eq!(request.headers[header::AUTHORIZATION], "Bearer managed-key");
    assert_eq!(request.headers[header::USER_AGENT], USER_AGENT);
    assert_eq!(
        request.body,
        Some(json!({
            "template": "reset-password",
            "to": "a@example.com",
            "variables": {
                "resetLink": "https://app.test/reset",
                "userEmail": "a@example.com"
            },
            "subject": "Reset"
        }))
    );
    server.abort();
}

#[tokio::test]
async fn bulk_is_one_request_and_preserves_shared_and_recipient_variables() {
    let (api_url, mut requests, server) = server().await;
    let sender = EmailSender::new(Some(config(api_url)));
    let options = SendBulkEmailsOptions::new(vec![
        BulkEmailRecipient::new(
            "one@example.com",
            VerifyEmailVariables::new("https://app.test/one", "one@example.com"),
        ),
        BulkEmailRecipient::without_variables("two@example.com"),
    ])
    .with_shared_variables([("appName".into(), "Example".into())].into_iter().collect());

    let result = sender.send_bulk(options).await;
    let request = requests.recv().await.unwrap();

    assert!(result.success);
    assert_eq!(result.failures, Some(json!("unchecked")));
    assert_eq!(request.operation, "bulk");
    assert_eq!(
        request.body,
        Some(json!({
            "template": "verify-email",
            "emails": [
                {
                    "to": "one@example.com",
                    "variables": {
                        "verificationUrl": "https://app.test/one",
                        "userEmail": "one@example.com"
                    }
                },
                { "to": "two@example.com", "variables": {} }
            ],
            "variables": { "appName": "Example" }
        }))
    );
    assert!(requests.try_recv().is_err());
    server.abort();
}

#[tokio::test]
async fn template_members_are_not_validated() {
    let (api_url, mut requests, server) = server().await;
    let sender = EmailSender::new(Some(config(api_url)));

    assert_eq!(
        sender.get_templates().await,
        vec![json!(3), json!({ "arbitrary": true })]
    );
    assert_eq!(requests.recv().await.unwrap().operation, "templates");
    server.abort();
}

#[tokio::test]
async fn missing_key_short_circuits_and_sender_debug_is_redacted() {
    let sender = EmailSender::new(Some(EmailConfig {
        api_key: Some(String::new()),
        api_url: Some("http://127.0.0.1:1".into()),
        ..EmailConfig::default()
    }));
    let result = sender
        .send(SendEmailOptions::new(
            "private@example.com",
            ResetPasswordVariables::new("secret-link", "private@example.com"),
        ))
        .await;

    assert_eq!(result.error, Some(json!("API key not configured")));
    let debug = format!("{sender:?}");
    assert!(!debug.contains("127.0.0.1"));
    assert!(!debug.contains("private@example.com"));
}

#[tokio::test]
async fn query_and_fragment_base_urls_resolve_operations_from_the_origin_root() {
    for suffix in ["/base?foo=1", "/base#fragment"] {
        let (origin, mut requests, server) = server().await;
        let sender = EmailSender::new(Some(config(format!("{origin}{suffix}"))));

        let result = sender
            .send(SendEmailOptions::new(
                "person@example.test",
                ResetPasswordVariables::new("secret-link", "person@example.test"),
            ))
            .await;

        assert!(result.success);
        assert_eq!(requests.recv().await.unwrap().operation, "send");
        server.abort();
    }
}

#[tokio::test]
async fn one_shot_wrappers_use_the_same_request_contract() {
    let (api_url, mut requests, server) = server().await;
    let single = send_email(
        SendEmailOptions::new(
            "person@example.test",
            ResetPasswordVariables::new("secret-link", "person@example.test"),
        ),
        Some(config(api_url.clone())),
    )
    .await;
    let bulk = send_bulk_emails(
        SendBulkEmailsOptions::new(vec![
            BulkEmailRecipient::<ResetPasswordVariables>::without_variables("person@example.test"),
        ]),
        Some(config(api_url)),
    )
    .await;

    assert!(single.success);
    assert!(bulk.success);
    assert_eq!(requests.recv().await.unwrap().operation, "send");
    assert_eq!(requests.recv().await.unwrap().operation, "bulk");
    server.abort();
}
