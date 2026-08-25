use axum::{
    Json,
    body::Body,
    http::StatusCode,
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

pub(super) fn message(status: StatusCode, message: impl Into<String>) -> Response {
    crate::axum::api_error_with_body(status, json!({"message": message.into()}))
}

pub(super) fn coded(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> Response {
    crate::axum::api_error(status, code, message.into())
}

pub(super) fn json(value: serde_json::Value) -> Response {
    Json(value).into_response()
}

pub(super) fn json_undefined() -> Response {
    let mut response = Response::new(Body::empty());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}
