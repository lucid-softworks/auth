use axum::{
    Json,
    body::{Bytes, to_bytes},
    extract::{FromRequest, FromRequestParts, Request},
    http::{StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

mod validation;

use validation::{deserialize_validated, query_value};

#[derive(Debug)]
pub(in crate::agent_auth::axum) struct AgentInputError(Box<Response>);

impl IntoResponse for AgentInputError {
    fn into_response(self) -> Response {
        *self.0
    }
}

impl AgentInputError {
    #[cfg(test)]
    fn status(&self) -> StatusCode {
        self.0.status()
    }

    #[cfg(test)]
    fn into_body(self) -> axum::body::Body {
        self.into_response().into_body()
    }
}

#[derive(Debug, Clone, Copy)]
pub(in crate::agent_auth::axum) enum FieldKind {
    String {
        min: Option<usize>,
    },
    Url,
    Number {
        coerce: bool,
        min: Option<Minimum>,
    },
    Boolean,
    StringArray {
        min: Option<usize>,
        max: Option<usize>,
    },
    CapabilityArray {
        min: Option<usize>,
        max: Option<usize>,
    },
    BatchRequestArray {
        min: Option<usize>,
        max: Option<usize>,
    },
    Record,
    PrimitiveRecord,
    JwkRecord,
    Enum(&'static [&'static str]),
}

#[derive(Debug, Clone, Copy)]
pub(in crate::agent_auth::axum) struct Minimum {
    value: f64,
    inclusive: bool,
}

impl Minimum {
    pub(in crate::agent_auth::axum) const fn inclusive(value: f64) -> Self {
        Self {
            value,
            inclusive: true,
        }
    }

    pub(in crate::agent_auth::axum) const fn exclusive(value: f64) -> Self {
        Self {
            value,
            inclusive: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(in crate::agent_auth::axum) struct Field {
    name: &'static str,
    kind: FieldKind,
    required: bool,
}

impl Field {
    pub(in crate::agent_auth::axum) const fn required(name: &'static str, kind: FieldKind) -> Self {
        Self {
            name,
            kind,
            required: true,
        }
    }

    pub(in crate::agent_auth::axum) const fn optional(name: &'static str, kind: FieldKind) -> Self {
        Self {
            name,
            kind,
            required: false,
        }
    }
}

pub(in crate::agent_auth::axum) trait AgentInput:
    DeserializeOwned
{
    const FIELDS: &'static [Field];
    const OPTIONAL_ROOT: bool = false;
}

#[derive(Debug)]
pub(in crate::agent_auth::axum) struct AgentJson<T>(pub T);

impl<S, T> FromRequest<S> for AgentJson<T>
where
    S: Send + Sync,
    T: AgentInput,
{
    type Rejection = AgentInputError;

    async fn from_request(request: Request, _: &S) -> Result<Self, Self::Rejection> {
        let content_type = request.headers().get(header::CONTENT_TYPE).cloned();
        let bytes = to_bytes(request.into_body(), 1024 * 1024)
            .await
            .map_err(|_| bad_request())?;
        validate_content_type(&bytes, content_type.as_ref())?;
        parse_json(&bytes).map(Self)
    }
}

#[derive(Debug)]
pub(in crate::agent_auth::axum) struct AgentQuery<T>(pub T);

#[derive(Debug)]
pub(in crate::agent_auth::axum) struct AgentRawJson;

impl<S> FromRequest<S> for AgentRawJson
where
    S: Send + Sync,
{
    type Rejection = AgentInputError;

    async fn from_request(request: Request, _: &S) -> Result<Self, Self::Rejection> {
        let content_type = request.headers().get(header::CONTENT_TYPE).cloned();
        let bytes = to_bytes(request.into_body(), 1024 * 1024)
            .await
            .map_err(|_| bad_request())?;
        validate_raw_json(&bytes, content_type.as_ref())?;
        Ok(Self)
    }
}

impl<S, T> FromRequestParts<S> for AgentQuery<T>
where
    S: Send + Sync,
    T: AgentInput,
{
    type Rejection = AgentInputError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let value = query_value(parts.uri.query());
        deserialize_validated(value, "query").map(Self)
    }
}

pub(in crate::agent_auth::axum) fn parse_json<T: AgentInput>(
    bytes: &Bytes,
) -> Result<T, AgentInputError> {
    if bytes.is_empty() && T::OPTIONAL_ROOT {
        return serde_json::from_value(Value::Object(Map::new()))
            .map_err(|error| validation(format!("[body] {error}")));
    }
    if bytes.is_empty() {
        return Err(validation(
            "[body] Invalid input: expected object, received undefined".into(),
        ));
    }
    let value = serde_json::from_slice(bytes).map_err(|_| bad_request())?;
    deserialize_validated(value, "body")
}

pub(in crate::agent_auth::axum) fn validate_raw_json(
    body: &Bytes,
    content_type: Option<&axum::http::HeaderValue>,
) -> Result<(), AgentInputError> {
    validate_content_type(body, content_type)?;
    if !body.is_empty() {
        serde_json::from_slice::<Value>(body).map_err(|_| bad_request())?;
    }
    Ok(())
}

fn validate_content_type(
    body: &Bytes,
    content_type: Option<&axum::http::HeaderValue>,
) -> Result<(), AgentInputError> {
    if body.is_empty() {
        return Ok(());
    }
    let raw = content_type
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let media_type = raw.split(';').next().unwrap_or_default().trim();
    if media_type.eq_ignore_ascii_case("application/json") {
        return Ok(());
    }
    let message = if raw.is_empty() {
        "Content-Type is required. Allowed types: application/json".to_owned()
    } else {
        format!("Content-Type \"{raw}\" is not allowed. Allowed types: application/json")
    };
    Err(rejection_with_status(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        message,
        "UNSUPPORTED_MEDIA_TYPE",
    ))
}

fn bad_request() -> AgentInputError {
    rejection("Invalid JSON in request body", "BAD_REQUEST")
}

fn validation(message: String) -> AgentInputError {
    rejection(message, "VALIDATION_ERROR")
}

fn rejection(message: impl Into<String>, code: &'static str) -> AgentInputError {
    rejection_with_status(StatusCode::BAD_REQUEST, message, code)
}

fn rejection_with_status(
    status: StatusCode,
    message: impl Into<String>,
    code: &'static str,
) -> AgentInputError {
    AgentInputError(Box::new(
        (
            status,
            Json(json!({"message": message.into(), "code": code})),
        )
            .into_response(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Example {
        name: String,
        enabled: Option<bool>,
    }

    impl AgentInput for Example {
        const FIELDS: &'static [Field] = &[
            Field::required("name", FieldKind::String { min: None }),
            Field::optional("enabled", FieldKind::Boolean),
        ];
    }

    #[test]
    fn aggregates_upstream_style_field_errors() {
        let error = parse_json::<Example>(&Bytes::from_static(br#"{"enabled":7}"#)).unwrap_err();
        let body = axum::body::to_bytes(error.into_body(), usize::MAX);
        let body = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(body)
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"message":"[body.name] Invalid input: expected string, received undefined; [body.enabled] Invalid input: expected boolean, received number","code":"VALIDATION_ERROR"})
        );
    }

    #[test]
    fn valid_input_is_deserialized() {
        let example =
            parse_json::<Example>(&Bytes::from_static(br#"{"name":"agent","enabled":true}"#))
                .unwrap();
        assert_eq!(example.name, "agent");
        assert_eq!(example.enabled, Some(true));
    }

    #[test]
    fn repeated_query_values_are_arrays_not_aliases() {
        assert_eq!(
            query_value(Some("name=one&name=two")),
            json!({"name":["one","two"]})
        );
    }

    #[test]
    fn rejects_non_json_content_type_exactly() {
        let response = validate_content_type(
            &Bytes::from_static(b"{}"),
            Some(&axum::http::HeaderValue::from_static(
                "text/plain;charset=UTF-8",
            )),
        )
        .unwrap_err();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
}

#[cfg(test)]
mod contract_tests;

#[cfg(test)]
mod constraints_tests;

#[cfg(test)]
mod media_tests;
