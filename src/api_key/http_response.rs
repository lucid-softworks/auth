use crate::{ApiKey, ApiKeyError};
use axum::{
    Json,
    response::{IntoResponse, Response},
};
use serde_json::{Map, Value, json};

pub(super) fn issued(api_key: ApiKey, key: String) -> Response {
    let mut value = serde_json::to_value(api_key).unwrap_or_else(|_| json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("key".into(), Value::String(key));
    }
    Json(value).into_response()
}

pub(super) fn list(
    api_keys: Vec<ApiKey>,
    total: usize,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Response {
    let mut response = json!({ "apiKeys": api_keys, "total": total });
    if let Some(object) = response.as_object_mut() {
        insert_optional_number(object, "limit", limit);
        insert_optional_number(object, "offset", offset);
    }
    Json(response).into_response()
}

pub(super) fn invalid_verification(error: ApiKeyError) -> Response {
    let (code, message, details) = match error {
        ApiKeyError::Disabled => ("KEY_DISABLED", "API Key is disabled", None),
        ApiKeyError::Expired => ("KEY_EXPIRED", "API Key has expired", None),
        ApiKeyError::UsageExceeded => (
            "USAGE_EXCEEDED",
            "API Key has reached its usage limit",
            None,
        ),
        ApiKeyError::RateLimited {
            retry_after_milliseconds,
        } => (
            "RATE_LIMITED",
            "Rate limit exceeded.",
            Some(json!({ "tryAgainIn": retry_after_milliseconds })),
        ),
        ApiKeyError::PermissionDenied => ("KEY_NOT_FOUND", "API Key not found", None),
        _ => ("INVALID_API_KEY", "Invalid API key.", None),
    };
    let mut error = json!({ "message": message, "code": code });
    if let (Some(object), Some(details)) = (error.as_object_mut(), details) {
        object.insert("details".into(), details);
    }
    Json(json!({ "valid": false, "error": error, "key": null })).into_response()
}

fn insert_optional_number(object: &mut Map<String, Value>, key: &str, value: Option<usize>) {
    if let Some(value) = value {
        object.insert(key.into(), json!(value));
    }
}
