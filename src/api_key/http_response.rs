use crate::ApiKey;
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

fn insert_optional_number(object: &mut Map<String, Value>, key: &str, value: Option<usize>) {
    if let Some(value) = value {
        object.insert(key.into(), json!(value));
    }
}
