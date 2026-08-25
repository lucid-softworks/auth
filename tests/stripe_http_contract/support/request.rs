use super::Fixture;
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

pub(crate) type ResponseParts = (StatusCode, HeaderMap, Value);

pub(crate) async fn post_json(fixture: &Fixture, path: &str, body: Value) -> ResponseParts {
    send(
        &fixture.app,
        Request::post(path)
            .header(header::ORIGIN, "http://localhost")
            .header(header::COOKIE, &fixture.cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

pub(crate) async fn send(app: &Router, request: Request<Body>) -> ResponseParts {
    let (status, headers, bytes) = send_bytes(app, request).await;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, headers, body)
}

pub(crate) async fn send_bytes(
    app: &Router,
    request: Request<Body>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}
