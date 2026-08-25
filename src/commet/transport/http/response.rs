use crate::commet::CommetProviderError;
use reqwest::{StatusCode, header::HeaderMap};
use serde_json::Value;

pub(super) type ParsedResponse = (StatusCode, HeaderMap, Value);

pub(super) struct RequestFailure {
    pub(super) error: CommetProviderError,
    pub(super) retryable: bool,
}

pub(super) async fn parse(response: reqwest::Response) -> Result<ParsedResponse, RequestFailure> {
    let status = response.status();
    let reason = status.canonical_reason().unwrap_or("").to_owned();
    let headers = response.headers().clone();
    let body = response.bytes().await.map_err(|_| RequestFailure {
        error: CommetProviderError::new("Commet response read failed"),
        retryable: false,
    })?;
    let value = serde_json::from_slice(&body).map_err(|_| RequestFailure {
        error: CommetProviderError::response(
            status.as_u16(),
            format!("Invalid JSON response: {} {reason}", status.as_u16()),
            String::from_utf8_lossy(&body),
        ),
        retryable: false,
    })?;
    Ok((status, headers, value))
}

pub(super) fn api_error(status: StatusCode, value: Value) -> CommetProviderError {
    let message = value
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("Request failed with status {}", status.as_u16()));
    CommetProviderError::response(status.as_u16(), message, value.to_string())
}

pub(super) fn request_failure(error: reqwest::Error) -> RequestFailure {
    let retryable = !error.is_builder();
    let message = if error.is_timeout() {
        "Commet HTTP request timed out"
    } else {
        "Commet HTTP request failed"
    };
    RequestFailure {
        retryable,
        error: CommetProviderError::new(message),
    }
}
