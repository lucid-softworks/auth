use axum::{
    body::to_bytes,
    extract::Request,
    http::{HeaderMap, header},
    response::Response,
};
use serde_json::Value;
use std::collections::BTreeMap;

use super::error;

pub(super) const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const BODY_LIMIT: usize = 1024 * 1024;

#[derive(Debug)]
pub(crate) struct CodeInput {
    pub(crate) client_id: Option<String>,
    pub(crate) user_id: Option<String>,
    pub(crate) scope: Option<String>,
    /// Every submitted JSON property or form field, retained for the OAuth
    /// Provider companion grant. Standalone handling deliberately validates
    /// only Better Auth's three base request fields.
    #[allow(dead_code)]
    pub(crate) parameters: BTreeMap<String, Vec<Value>>,
}

#[derive(Debug)]
pub(super) struct TokenInput {
    pub(super) device_code: String,
    pub(super) client_id: String,
}

pub(crate) async fn code(
    request: Request,
    client_id_optional: bool,
) -> Result<(HeaderMap, CodeInput), Response> {
    let content_type = content_type(request.headers());
    let headers = request.headers().clone();
    let bytes = body_bytes(request).await?;
    match media_type(&content_type) {
        "application/json" => code_json(&bytes, client_id_optional).map(|input| (headers, input)),
        "application/x-www-form-urlencoded" => {
            code_form(&bytes, client_id_optional).map(|input| (headers, input))
        }
        _ => Err(error::unsupported_media_type(
            &presented_content_type(&content_type),
            "application/json, application/x-www-form-urlencoded",
        )),
    }
}

pub(super) async fn token(request: Request) -> Result<(HeaderMap, TokenInput), Response> {
    let (headers, value) = json_request(request).await?;
    let mut issues = Vec::new();
    match value.get("grant_type").and_then(Value::as_str) {
        Some(DEVICE_GRANT_TYPE) => {}
        _ => issues.push(format!(
            "[body.grant_type] Invalid input: expected \"{DEVICE_GRANT_TYPE}\""
        )),
    }
    let device_code = required_string(&value, "device_code", &mut issues);
    let client_id = required_string(&value, "client_id", &mut issues);
    if !issues.is_empty() {
        return Err(error::validation(issues.join("; ")));
    }
    Ok((
        headers,
        TokenInput {
            device_code: device_code.expect("validated device_code"),
            client_id: client_id.expect("validated client_id"),
        },
    ))
}

pub(super) async fn decision(request: Request) -> Result<(HeaderMap, String), Response> {
    let (headers, value) = json_request(request).await?;
    let mut issues = Vec::new();
    let user_code = required_string(&value, "userCode", &mut issues);
    if !issues.is_empty() {
        return Err(error::validation(issues.join("; ")));
    }
    Ok((headers, user_code.expect("validated userCode")))
}

#[allow(clippy::result_large_err)]
fn code_json(bytes: &[u8], client_id_optional: bool) -> Result<CodeInput, Response> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| error::invalid_json())?;
    let object = value.as_object().ok_or_else(|| {
        error::protocol(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "[body] Invalid input: expected object",
            false,
        )
    })?;
    let mut issues = Vec::new();
    let client_id = optional_string(&value, "client_id", &mut issues);
    let user_id = optional_string(&value, "user_id", &mut issues);
    let scope = optional_string(&value, "scope", &mut issues);
    if !client_id_optional && !object.contains_key("client_id") {
        issues.insert(
            0,
            "[body.client_id] Invalid input: expected string, received undefined".into(),
        );
    }
    if !issues.is_empty() {
        return Err(error::protocol(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            issues.join("; "),
            false,
        ));
    }
    Ok(CodeInput {
        client_id: nonempty(client_id),
        user_id: nonempty(user_id),
        scope: nonempty(scope),
        parameters: object
            .iter()
            .map(|(name, value)| {
                let values = match value {
                    Value::Array(values) if name == "resource" => values.clone(),
                    value => vec![value.clone()],
                };
                (name.clone(), values)
            })
            .collect(),
    })
}

#[allow(clippy::result_large_err)]
fn code_form(bytes: &[u8], client_id_optional: bool) -> Result<CodeInput, Response> {
    let mut fields = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in url::form_urlencoded::parse(bytes) {
        fields
            .entry(name.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    for field in ["client_id", "user_id", "scope"] {
        let values = fields
            .get(field)
            .into_iter()
            .flatten()
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if values.len() > 1 {
            return Err(error::protocol(
                axum::http::StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("{field} must not be repeated"),
                true,
            ));
        }
    }
    let first = |name: &str| {
        fields
            .get(name)
            .and_then(|values| values.iter().find(|value| !value.is_empty()))
            .cloned()
    };
    let client_id = first("client_id");
    if !client_id_optional && client_id.is_none() && !fields.contains_key("client_id") {
        return Err(error::protocol(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "[body.client_id] Invalid input: expected string, received undefined",
            false,
        ));
    }
    Ok(CodeInput {
        client_id,
        user_id: first("user_id"),
        scope: first("scope"),
        parameters: fields
            .into_iter()
            .map(|(name, values)| {
                (
                    name,
                    values.into_iter().map(Value::String).collect::<Vec<_>>(),
                )
            })
            .collect(),
    })
}

async fn json_request(request: Request) -> Result<(HeaderMap, Value), Response> {
    let content_type = content_type(request.headers());
    if media_type(&content_type) != "application/json" {
        return Err(error::unsupported_media_type(
            &presented_content_type(&content_type),
            "application/json",
        ));
    }
    let headers = request.headers().clone();
    let bytes = body_bytes(request).await?;
    let value = serde_json::from_slice(&bytes).map_err(|_| error::invalid_json())?;
    Ok((headers, value))
}

async fn body_bytes(request: Request) -> Result<axum::body::Bytes, Response> {
    to_bytes(request.into_body(), BODY_LIMIT)
        .await
        .map_err(|_| {
            error::generic(
                axum::http::StatusCode::BAD_REQUEST,
                "Request body is too large",
                "BAD_REQUEST",
            )
        })
}

fn required_string(value: &Value, field: &str, issues: &mut Vec<String>) -> Option<String> {
    match value.get(field) {
        Some(Value::String(value)) => Some(value.clone()),
        Some(value) => {
            issues.push(format!(
                "[body.{field}] Invalid input: expected string, received {}",
                value_kind(value)
            ));
            None
        }
        None => {
            issues.push(format!(
                "[body.{field}] Invalid input: expected string, received undefined"
            ));
            None
        }
    }
}

fn optional_string(value: &Value, field: &str, issues: &mut Vec<String>) -> Option<String> {
    match value.get(field) {
        Some(Value::String(value)) => Some(value.clone()),
        Some(value) => {
            issues.push(format!(
                "[body.{field}] Invalid input: expected string, received {}",
                value_kind(value)
            ));
            None
        }
        None => None,
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn content_type(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned()
}

fn media_type(content_type: &str) -> &str {
    content_type.split(';').next().unwrap_or("").trim()
}

fn presented_content_type(content_type: &str) -> String {
    if content_type.is_empty() {
        "unknown".into()
    } else {
        content_type.into()
    }
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use serde_json::json;

    #[tokio::test]
    async fn parser_retains_oauth_companion_fields_and_repeated_resources() {
        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                "client_id=client&client_secret=secret&resource=https%3A%2F%2Fa&resource=https%3A%2F%2Fb",
            ))
            .unwrap();
        let (_, input) = code(request, true).await.unwrap();
        assert_eq!(
            input.parameters["client_secret"],
            vec![Value::String("secret".into())]
        );
        assert_eq!(
            input.parameters["resource"],
            vec![
                Value::String("https://a".into()),
                Value::String("https://b".into())
            ]
        );

        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "client_id":"client",
                    "client_assertion":"assertion",
                    "client_assertion_type":"urn:assertion",
                    "resource":["https://a","https://b"]
                })
                .to_string(),
            ))
            .unwrap();
        let (_, input) = code(request, true).await.unwrap();
        assert_eq!(
            input.parameters["resource"],
            vec![
                Value::String("https://a".into()),
                Value::String("https://b".into())
            ]
        );

        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"scope":"openid"}).to_string()))
            .unwrap();
        assert!(code(request, true).await.is_ok());
    }
}
