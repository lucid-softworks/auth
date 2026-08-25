use super::Fixture;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

pub(crate) async fn post(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let mut request = Request::post(path)
        .header(header::ORIGIN, "http://localhost")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = &fixture.cookie {
        request = request.header(header::COOKIE, cookie);
    }
    send(request.body(Body::from(body.to_string())).unwrap(), fixture).await
}

pub(crate) async fn get(fixture: &Fixture, path: &str) -> (StatusCode, Value) {
    let mut request = Request::get(path).header(header::ORIGIN, "http://localhost");
    if let Some(cookie) = &fixture.cookie {
        request = request.header(header::COOKIE, cookie);
    }
    send(request.body(Body::empty()).unwrap(), fixture).await
}

pub(crate) async fn get_redirect(fixture: &Fixture, path: &str) -> (StatusCode, Option<String>) {
    let mut request = Request::get(path).header(header::ORIGIN, "http://localhost");
    if let Some(cookie) = &fixture.cookie {
        request = request.header(header::COOKIE, cookie);
    }
    let response = fixture
        .app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    (response.status(), location)
}

pub(crate) async fn raw_post(
    fixture: &Fixture,
    path: &str,
    body: &str,
    authorization: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(authorization) = authorization {
        request = request.header(header::AUTHORIZATION, authorization);
    }
    send(request.body(Body::from(body.to_owned())).unwrap(), fixture).await
}

async fn send(request: Request<Body>, fixture: &Fixture) -> (StatusCode, Value) {
    let response = fixture.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}
