use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

pub(crate) type ResponseParts = (StatusCode, HeaderMap, Value);

pub(crate) async fn get(app: &Router, path: &str, cookie: Option<&str>) -> ResponseParts {
    let mut request = Request::get(path).header(header::ORIGIN, "http://localhost");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    send(app, request.body(Body::empty()).unwrap()).await
}

pub(crate) async fn post(
    app: &Router,
    path: &str,
    cookie: Option<&str>,
    body: Value,
) -> ResponseParts {
    let mut request = Request::post(path)
        .header(header::ORIGIN, "http://localhost")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    send(app, request.body(Body::from(body.to_string())).unwrap()).await
}

pub(crate) async fn send(app: &Router, request: Request<Body>) -> ResponseParts {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, headers, body)
}
