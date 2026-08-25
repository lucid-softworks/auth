use super::PolarHttpClient;
use crate::polar::{
    schema::{OutboundKind, normalize_outbound},
    transport::{PolarCustomer, PolarProviderError, PolarResponseKind, normalize_sdk_value},
};
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde_json::{Value, json};
use std::fmt;
use url::Url;

impl PolarHttpClient {
    pub(super) fn url(&self, path: &str) -> Result<Url, PolarProviderError> {
        self.api_base
            .join(path.trim_start_matches('/'))
            .map_err(|error| PolarProviderError::new(error.to_string()))
    }

    pub(super) async fn organization_json<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        query: &[(String, String)],
        expected: &[StatusCode],
        kind: PolarResponseKind,
    ) -> Result<Value, PolarProviderError> {
        self.request_json(
            method,
            path,
            body,
            query,
            self.access_token.as_ref(),
            expected,
            kind,
        )
        .await
    }

    pub(super) async fn portal_json<B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: Option<&B>,
        query: &[(String, String)],
        customer_session: &str,
        kind: PolarResponseKind,
    ) -> Result<Value, PolarProviderError> {
        self.request_json(
            Method::GET,
            path,
            body,
            query,
            customer_session,
            &[StatusCode::OK],
            kind,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_json<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        query: &[(String, String)],
        bearer: &str,
        expected: &[StatusCode],
        kind: PolarResponseKind,
    ) -> Result<Value, PolarProviderError> {
        let mut request = self
            .http
            .request(method, self.url(path)?)
            .bearer_auth(bearer)
            .header(reqwest::header::ACCEPT, "application/json")
            .query(query);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(transport_error)?;
        let status = response.status();
        let bytes = bounded_body(response, self.response_limit).await?;
        if !expected.contains(&status) {
            return Err(provider_response(status, &bytes));
        }
        let value = serde_json::from_slice(&bytes).map_err(|error| {
            PolarProviderError::new(format!("Polar response was invalid: {error}"))
        })?;
        normalize_sdk_value(value, kind)
    }

    pub(super) async fn organization_empty(
        &self,
        method: Method,
        path: &str,
        expected: StatusCode,
    ) -> Result<(), PolarProviderError> {
        let response = self
            .http
            .request(method, self.url(path)?)
            .bearer_auth(self.access_token.as_ref())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(transport_error)?;
        let status = response.status();
        let bytes = bounded_body(response, self.response_limit).await?;
        if status == expected {
            Ok(())
        } else {
            Err(provider_response(status, &bytes))
        }
    }
}

pub(super) fn customer(value: Value) -> Result<PolarCustomer, PolarProviderError> {
    let id = value["id"]
        .as_str()
        .ok_or_else(|| PolarProviderError::new("Polar customer has no ID"))?
        .to_owned();
    let external_id = value
        .get("externalId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(PolarCustomer {
        id,
        external_id,
        value,
    })
}

pub(super) fn outbound_body<T: Serialize>(
    value: &T,
    kind: OutboundKind,
) -> Result<Value, PolarProviderError> {
    let value = serde_json::to_value(value)
        .map_err(|error| PolarProviderError::new(format!("Polar request was invalid: {error}")))?;
    normalize_outbound(value, kind).map_err(outbound_error)
}

pub(super) fn outbound_query<T: Serialize>(
    value: &T,
    kind: OutboundKind,
) -> Result<Vec<(String, String)>, PolarProviderError> {
    let value = serde_json::to_value(value)
        .map_err(|error| PolarProviderError::new(format!("Polar query was invalid: {error}")))?;
    let value = normalize_outbound(value, kind).map_err(outbound_error)?;
    let object = value
        .as_object()
        .ok_or_else(|| PolarProviderError::new("Polar SDK query was not an object"))?;
    let mut query = Vec::new();
    for (key, value) in object {
        append_query(&mut query, key, value)?;
    }
    Ok(query)
}

fn append_query(
    query: &mut Vec<(String, String)>,
    key: &str,
    value: &Value,
) -> Result<(), PolarProviderError> {
    match value {
        Value::Null => {}
        Value::Bool(value) => query.push((key.into(), value.to_string())),
        Value::Number(value) => query.push((key.into(), value.to_string())),
        Value::String(value) => query.push((key.into(), value.clone())),
        Value::Object(values) => {
            for (nested_key, nested_value) in values {
                append_query(query, &format!("{key}[{nested_key}]"), nested_value)?;
            }
        }
        Value::Array(_) => {
            return Err(PolarProviderError::new(
                "Polar SDK query contained an unsupported array",
            ));
        }
    }
    Ok(())
}

fn outbound_error(error: crate::polar::schema::SchemaError) -> PolarProviderError {
    PolarProviderError::new(format!("Polar SDK request validation failed: {error}"))
}

pub(super) fn page(
    value: Value,
    requested_page: Option<f64>,
    requested_limit: Option<f64>,
) -> Result<Value, PolarProviderError> {
    let page = requested_page.unwrap_or(1.0);
    let limit = requested_limit.unwrap_or(10.0);
    let has_next = value["pagination"]["maxPage"]
        .as_f64()
        .is_some_and(|max_page| max_page > page)
        && value["items"]
            .as_array()
            .is_some_and(|items| (items.len() as f64) >= limit);
    let mut output = serde_json::Map::from_iter([("result".into(), value)]);
    if has_next {
        output.insert("~next".into(), json!({ "page": json_number(page + 1.0)? }));
    }
    Ok(Value::Object(output))
}

fn json_number(value: f64) -> Result<Value, PolarProviderError> {
    serde_json::Number::from_f64(value)
        .map(Value::Number)
        .ok_or_else(|| PolarProviderError::new("Polar pagination value is not finite"))
}

pub(super) fn path_segment(value: &str) -> String {
    const PATH_SEGMENT: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'#')
        .add(b'%')
        .add(b'/')
        .add(b'<')
        .add(b'>')
        .add(b'?')
        .add(b'`')
        .add(b'{')
        .add(b'}');
    percent_encoding::utf8_percent_encode(value, PATH_SEGMENT).to_string()
}

async fn bounded_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, PolarProviderError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(PolarProviderError::new(
            "Polar response exceeded the size limit",
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(PolarProviderError::new(
                "Polar response exceeded the size limit",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn provider_response(status: StatusCode, body: &[u8]) -> PolarProviderError {
    let response = String::from_utf8_lossy(body).into_owned();
    let message = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("detail")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| {
                    value
                        .get("message")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
        })
        .unwrap_or_else(|| format!("Polar returned HTTP {}", status.as_u16()));
    PolarProviderError::response(status.as_u16(), message, response)
}

pub(super) fn transport_error(error: impl fmt::Display) -> PolarProviderError {
    PolarProviderError::new(format!("Polar request failed: {error}"))
}
