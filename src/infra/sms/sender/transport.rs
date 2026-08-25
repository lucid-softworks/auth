use reqwest::{StatusCode, header};
use serde_json::{Map, Value};

pub(super) async fn execute(request: reqwest::RequestBuilder) -> Result<Value, RequestFailure> {
    let response = request
        .send()
        .await
        .map_err(|error| RequestFailure::Exception(error.to_string()))?;
    let status = response.status();
    let response_kind = response_kind(response.headers());
    let body = response
        .bytes()
        .await
        .map_err(|error| RequestFailure::Exception(error.to_string()))?;
    if !status.is_success() {
        return Err(RequestFailure::Http(http_error(status, &body)));
    }
    Ok(success_value(response_kind, &body))
}

pub(super) enum RequestFailure {
    Http(Value),
    Exception(String),
}

#[derive(Clone, Copy)]
enum ResponseKind {
    Json,
    Text,
    Blob,
}

fn response_kind(headers: &reqwest::header::HeaderMap) -> ResponseKind {
    let Some(content_type) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return ResponseKind::Json;
    };
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if media_type == "application/json"
        || (media_type.starts_with("application/") && media_type.ends_with("+json"))
    {
        ResponseKind::Json
    } else if media_type.starts_with("text/")
        || matches!(
            media_type.as_str(),
            "image/svg" | "application/xml" | "application/xhtml" | "application/html"
        )
    {
        ResponseKind::Text
    } else {
        ResponseKind::Blob
    }
}

fn success_value(kind: ResponseKind, body: &[u8]) -> Value {
    match kind {
        ResponseKind::Json => serde_json::from_slice(body)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(body).into_owned())),
        ResponseKind::Text => Value::String(String::from_utf8_lossy(body).into_owned()),
        ResponseKind::Blob => Value::Object(Map::new()),
    }
}

fn http_error(status: StatusCode, body: &[u8]) -> Value {
    let message = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .and_then(|object| object.get("message").cloned())
        .filter(js_truthy);
    message.unwrap_or_else(|| Value::String(format!("HTTP {}", status.as_u16())))
}

fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_preserves_truthy_messages_and_falls_back_for_falsey_values() {
        assert_eq!(
            http_error(StatusCode::BAD_REQUEST, br#"{"message":"invalid"}"#),
            Value::String("invalid".into())
        );
        assert_eq!(
            http_error(StatusCode::BAD_REQUEST, br#"{"message":7}"#),
            Value::from(7)
        );
        assert_eq!(
            http_error(StatusCode::BAD_REQUEST, br#"{"message":false}"#),
            Value::String("HTTP 400".into())
        );
    }

    #[test]
    fn malformed_json_is_returned_as_a_string() {
        assert_eq!(
            success_value(ResponseKind::Json, b"not-json"),
            Value::String("not-json".into())
        );
    }
}
