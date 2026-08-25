use super::*;
use crate::infra::email::{
    BulkEmailRecipient, EmailApiOptions, ResetPasswordVariables, SendBulkEmailsOptions,
};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderValue, Response, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex;

struct Reply {
    status: StatusCode,
    content_type: Option<&'static str>,
    content_encoding: Option<&'static str>,
    body: &'static [u8],
}

type Replies = Arc<Mutex<VecDeque<Reply>>>;

async fn reply(State(replies): State<Replies>) -> Response<Body> {
    let reply = replies.lock().await.pop_front().expect("fixture reply");
    let mut response = Response::builder().status(reply.status);
    if let Some(content_type) = reply.content_type {
        response = response.header("content-type", HeaderValue::from_static(content_type));
    }
    if let Some(content_encoding) = reply.content_encoding {
        response = response.header(
            "content-encoding",
            HeaderValue::from_static(content_encoding),
        );
    }
    response.body(Body::from(reply.body)).unwrap()
}

async fn server(replies: Vec<Reply>) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/api/v1/email/send", post(reply))
        .route("/api/v1/email/send-bulk", post(reply))
        .route("/api/v1/email/templates", get(reply))
        .with_state(Arc::new(Mutex::new(replies.into())));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), task)
}

async fn slow_reply(State(calls): State<Arc<AtomicUsize>>) -> axum::Json<Value> {
    calls.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(40)).await;
    axum::Json(json!({ "messageId": "slow" }))
}

async fn slow_server() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/api/v1/email/send", post(slow_reply))
        .with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), calls, task)
}

fn sender(api_url: String) -> EmailSender {
    EmailSender::new(Some(EmailConfig {
        api_key: Some("managed-key".into()),
        api_url: Some(api_url),
        ..EmailConfig::default()
    }))
}

fn single_options() -> SendEmailOptions<ResetPasswordVariables> {
    SendEmailOptions::new(
        "person@example.test",
        ResetPasswordVariables::new("secret-link", "person@example.test"),
    )
}

fn bulk_options() -> SendBulkEmailsOptions<ResetPasswordVariables> {
    SendBulkEmailsOptions::new(vec![
        BulkEmailRecipient::without_variables("same@example.test"),
        BulkEmailRecipient::without_variables("other@example.test"),
        BulkEmailRecipient::without_variables("same@example.test"),
    ])
}

fn json_reply(body: &'static str) -> Reply {
    Reply {
        status: StatusCode::OK,
        content_type: Some("application/json"),
        content_encoding: None,
        body: body.as_bytes(),
    }
}

#[tokio::test]
async fn single_response_shapes_match_the_oracle() {
    let (api_url, task) = server(vec![
        json_reply("{}"),
        json_reply(r#"{"success":false,"messageId":"provider-id"}"#),
        json_reply("[]"),
        json_reply(r#""ok""#),
        json_reply("42"),
        json_reply("false"),
        json_reply("null"),
    ])
    .await;
    let sender = sender(api_url);

    let empty = sender.send(single_options()).await;
    assert!(empty.success);
    assert!(empty.message_id.is_none());
    let ignored_success = sender.send(single_options()).await;
    assert!(ignored_success.success);
    assert_eq!(ignored_success.message_id, Some(json!("provider-id")));
    for _ in 0..4 {
        assert_eq!(
            sender.send(single_options()).await.error,
            Some(json!("Failed to parse JSON"))
        );
    }
    assert_eq!(
        sender.send(single_options()).await.error,
        Some(json!(
            "Cannot read properties of null (reading 'messageId')"
        ))
    );
    task.abort();
}

#[tokio::test]
async fn single_http_and_malformed_errors_match_the_oracle() {
    let (api_url, task) = server(vec![
        Reply {
            status: StatusCode::TOO_MANY_REQUESTS,
            content_type: Some("application/json"),
            content_encoding: None,
            body: br#"{"message":"rate limited"}"#,
        },
        Reply {
            status: StatusCode::SERVICE_UNAVAILABLE,
            content_type: None,
            content_encoding: None,
            body: b"",
        },
        json_reply("not json"),
    ])
    .await;
    let sender = sender(api_url);

    assert_eq!(
        sender.send(single_options()).await.error,
        Some(json!("rate limited"))
    );
    assert_eq!(
        sender.send(single_options()).await.error,
        Some(json!("HTTP 503"))
    );
    assert_eq!(
        sender.send(single_options()).await.error,
        Some(json!("Failed to parse JSON"))
    );
    task.abort();
}

#[tokio::test]
async fn http_error_messages_preserve_truthy_values_and_fallback_for_falsey_values() {
    let (api_url, task) = server(vec![
        Reply {
            status: StatusCode::BAD_REQUEST,
            content_type: Some("application/json"),
            content_encoding: None,
            body: br#"{"message":7}"#,
        },
        Reply {
            status: StatusCode::BAD_REQUEST,
            content_type: Some("application/json"),
            content_encoding: None,
            body: br#"{"message":{}}"#,
        },
        Reply {
            status: StatusCode::BAD_REQUEST,
            content_type: Some("application/json"),
            content_encoding: None,
            body: br#"{"message":false}"#,
        },
    ])
    .await;
    let sender = sender(api_url);

    assert_eq!(sender.send(single_options()).await.error, Some(json!(7)));
    assert_eq!(sender.send(single_options()).await.error, Some(json!({})));
    assert_eq!(
        sender.send(single_options()).await.error,
        Some(json!("HTTP 400"))
    );
    task.abort();
}

#[tokio::test]
async fn gzip_json_responses_are_decoded_like_fetch() {
    const GZIP_RESPONSE: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xab, 0x56, 0xca, 0x4d, 0x2d,
        0x2e, 0x4e, 0x4c, 0x4f, 0xf5, 0x4c, 0x51, 0xb2, 0x52, 0x4a, 0xce, 0xcf, 0x2d, 0x28, 0x02,
        0xf2, 0x53, 0x53, 0x94, 0x6a, 0x01, 0x54, 0xba, 0x8b, 0x83, 0x1a, 0x00, 0x00, 0x00,
    ];
    let (api_url, task) = server(vec![Reply {
        status: StatusCode::OK,
        content_type: Some("application/json"),
        content_encoding: Some("gzip"),
        body: GZIP_RESPONSE,
    }])
    .await;

    let result = sender(api_url).send(single_options()).await;
    assert!(result.success);
    assert_eq!(result.message_id, Some(json!("compressed")));
    task.abort();
}

#[tokio::test]
async fn configured_timeout_fails_once_and_zero_disables_the_timer() {
    let (api_url, calls, task) = slow_server().await;
    let timed = EmailSender::new(Some(EmailConfig {
        api_key: Some("managed-key".into()),
        api_url: Some(api_url.clone()),
        api_options: Some(EmailApiOptions { timeout: Some(10) }),
        ..EmailConfig::default()
    }));
    let failure = timed.send(single_options()).await;
    assert!(!failure.success);
    assert!(failure.error.is_some());

    let untimed = EmailSender::new(Some(EmailConfig {
        api_key: Some("managed-key".into()),
        api_url: Some(api_url),
        api_options: Some(EmailApiOptions { timeout: Some(0) }),
        ..EmailConfig::default()
    }));
    let success = untimed.send(single_options()).await;
    assert!(success.success);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    task.abort();
}

#[tokio::test]
async fn bulk_shapes_and_duplicate_failure_keys_match_the_oracle() {
    let (api_url, task) = server(vec![
        json_reply(r#"{"success":false,"failures":"unchecked"}"#),
        json_reply("{}"),
        json_reply("[]"),
        json_reply("null"),
        Reply {
            status: StatusCode::FORBIDDEN,
            content_type: Some("application/json"),
            content_encoding: None,
            body: br#"{"message":"denied"}"#,
        },
    ])
    .await;
    let sender = sender(api_url);

    let accepted = sender.send_bulk(bulk_options()).await;
    assert!(!accepted.success);
    assert_eq!(accepted.failures, Some(json!("unchecked")));
    for message in [
        "Failed to parse JSON",
        "Failed to parse JSON",
        "Cannot read properties of null (reading 'success')",
        "denied",
    ] {
        let result = sender.send_bulk(bulk_options()).await;
        assert_eq!(
            result.failures,
            Some(json!({
                "same@example.test": [{ "error": message }],
                "other@example.test": [{ "error": message }]
            }))
        );
    }
    task.abort();
}

#[tokio::test]
async fn template_listing_accepts_only_arrays_and_swallows_failures() {
    let (api_url, task) = server(vec![
        json_reply(r#"[null,"template",{"arbitrary":true}]"#),
        json_reply(r#"{"templates":[]}"#),
        json_reply("not json"),
        Reply {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            content_type: None,
            content_encoding: None,
            body: b"bad",
        },
    ])
    .await;
    let sender = sender(api_url);

    assert_eq!(
        sender.get_templates().await,
        vec![Value::Null, json!("template"), json!({ "arbitrary": true })]
    );
    for _ in 0..3 {
        assert!(sender.get_templates().await.is_empty());
    }
    task.abort();
}

#[tokio::test]
async fn missing_key_bulk_and_templates_short_circuit() {
    let sender = EmailSender::new(Some(EmailConfig {
        api_key: Some(String::new()),
        api_url: Some("http://127.0.0.1:1".into()),
        ..EmailConfig::default()
    }));

    let bulk = sender.send_bulk(bulk_options()).await;
    assert_eq!(
        bulk.failures,
        Some(json!({
            "same@example.test": [{ "error": "API key not configured" }],
            "other@example.test": [{ "error": "API key not configured" }]
        }))
    );
    assert!(sender.get_templates().await.is_empty());
}
