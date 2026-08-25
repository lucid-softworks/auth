use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

pub(super) fn generic(status: StatusCode, message: impl Into<String>, code: &str) -> Response {
    (
        status,
        Json(json!({
            "message": message.into(),
            "code": code,
        })),
    )
        .into_response()
}

pub(super) fn protocol(
    status: StatusCode,
    error: &str,
    description: impl Into<String>,
    no_store_response: bool,
) -> Response {
    let response = (
        status,
        Json(json!({
            "error": error,
            "error_description": description.into(),
        })),
    )
        .into_response();
    if no_store_response {
        no_store(response)
    } else {
        response
    }
}

pub(super) fn internal(description: impl Into<String>, no_store_response: bool) -> Response {
    protocol(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        description,
        no_store_response,
    )
}

pub(in crate::device_authorization) fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

pub(super) fn unsupported_media_type(presented: &str, allowed: &str) -> Response {
    generic(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        format!("Content-Type \"{presented}\" is not allowed. Allowed types: {allowed}"),
        "UNSUPPORTED_MEDIA_TYPE",
    )
}

pub(super) fn invalid_json() -> Response {
    generic(
        StatusCode::BAD_REQUEST,
        "Invalid JSON in request body",
        "BAD_REQUEST",
    )
}

pub(super) fn validation(message: impl Into<String>) -> Response {
    generic(StatusCode::BAD_REQUEST, message, "VALIDATION_ERROR")
}
