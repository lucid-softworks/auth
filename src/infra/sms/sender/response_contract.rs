use super::*;
use crate::infra::sms::SmsApiOptions;
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderValue, Response, StatusCode},
    routing::post,
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
        .route("/api/v1/sms/send", post(reply))
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
        .route("/api/v1/sms/send", post(slow_reply))
        .with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), calls, task)
}

fn json_reply(body: &'static str) -> Reply {
    Reply {
        status: StatusCode::OK,
        content_type: Some("application/json"),
        content_encoding: None,
        body: body.as_bytes(),
    }
}

fn sender(api_url: String) -> SmsSender {
    SmsSender::new(Some(SmsConfig {
        api_key: Some("managed-key".into()),
        api_url: Some(api_url),
        ..SmsConfig::default()
    }))
}

fn options() -> SendSmsOptions {
    SendSmsOptions::new("person", "code")
}

#[tokio::test]
async fn success_objects_pass_through_unvalidated_message_ids() {
    let (api_url, task) = server(vec![
        json_reply("{}"),
        json_reply(r#"{"success":false,"messageId":7}"#),
        json_reply(r#"{"messageId":null}"#),
        json_reply(r#"{"messageId":{"nested":true}}"#),
    ])
    .await;
    let sender = sender(api_url);

    let empty = sender.send(options()).await;
    assert!(empty.success);
    assert!(empty.message_id.is_none());
    assert_eq!(sender.send(options()).await.message_id, Some(json!(7)));
    assert_eq!(sender.send(options()).await.message_id, Some(Value::Null));
    assert_eq!(
        sender.send(options()).await.message_id,
        Some(json!({ "nested": true }))
    );
    task.abort();
}

#[tokio::test]
async fn non_object_success_bodies_fail_to_parse() {
    let (api_url, task) = server(vec![
        json_reply("[]"),
        json_reply(r#""ok""#),
        json_reply("42"),
        json_reply("false"),
        json_reply("null"),
        json_reply("not json"),
    ])
    .await;
    let sender = sender(api_url);

    for _ in 0..6 {
        assert_eq!(
            sender.send(options()).await.error,
            Some(json!("Failed to parse JSON"))
        );
    }
    task.abort();
}

#[tokio::test]
async fn http_errors_preserve_truthy_values_and_fallback_for_falsey_values() {
    let bodies: &[&'static [u8]] = &[
        br#"{"message":"rate limited"}"#,
        br#"{"message":7}"#,
        br#"{"message":true}"#,
        br#"{"message":[]}"#,
        br#"{"message":{}}"#,
        br#"{"message":""}"#,
        br#"{"message":0}"#,
        br#"{"message":false}"#,
        br#"{"message":null}"#,
    ];
    let replies = bodies
        .iter()
        .map(|body| Reply {
            status: StatusCode::BAD_REQUEST,
            content_type: Some("application/json"),
            content_encoding: None,
            body,
        })
        .collect();
    let (api_url, task) = server(replies).await;
    let sender = sender(api_url);

    for expected in [
        json!("rate limited"),
        json!(7),
        json!(true),
        json!([]),
        json!({}),
    ] {
        assert_eq!(sender.send(options()).await.error, Some(expected));
    }
    for _ in 0..4 {
        assert_eq!(sender.send(options()).await.error, Some(json!("HTTP 400")));
    }
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

    let result = sender(api_url).send(options()).await;
    assert!(result.success);
    assert_eq!(result.message_id, Some(json!("compressed")));
    task.abort();
}

#[tokio::test]
async fn configured_timeout_fails_once_and_zero_disables_the_timer() {
    let (api_url, calls, task) = slow_server().await;
    let timed = SmsSender::new(Some(SmsConfig {
        api_key: Some("managed-key".into()),
        api_url: Some(api_url.clone()),
        api_options: Some(SmsApiOptions { timeout: Some(10) }),
        ..SmsConfig::default()
    }));

    assert!(!timed.send(options()).await.success);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let untimed = SmsSender::new(Some(SmsConfig {
        api_key: Some("managed-key".into()),
        api_url: Some(api_url),
        api_options: Some(SmsApiOptions { timeout: Some(0) }),
        ..SmsConfig::default()
    }));
    assert!(untimed.send(options()).await.success);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    task.abort();
}
