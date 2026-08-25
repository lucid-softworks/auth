use super::{AutumnClient, AutumnOperation, AutumnProviderError};
use crate::autumn::schema::{normalize_inbound, normalize_outbound};
use async_trait::async_trait;
use reqwest::{StatusCode, header};
use serde_json::{Value, json};
use std::{fmt, time::Duration};
use url::Url;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
const USER_AGENT: &str = "speakeasy-sdk/typescript 0.10.18 2.882.0 2.3.0 @useautumn/sdk";

/// Native HTTP implementation of Autumn's generated TypeScript SDK behavior.
#[derive(Clone)]
pub struct AutumnHttpClient {
    http: reqwest::Client,
    response_limit: usize,
}

impl AutumnHttpClient {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_TIMEOUT, DEFAULT_RESPONSE_LIMIT)
            .expect("Autumn HTTP client defaults are valid")
    }

    /// Construct a client with explicit resource limits.
    pub fn with_limits(
        timeout: Duration,
        response_limit: usize,
    ) -> Result<Self, AutumnProviderError> {
        if timeout.is_zero() || response_limit == 0 {
            return Err(AutumnProviderError::internal(
                "Autumn timeout and response limit must be greater than zero",
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| AutumnProviderError::internal("Unexpected HTTP client error"))?;
        Ok(Self {
            http,
            response_limit,
        })
    }
}

impl Default for AutumnHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AutumnHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AutumnHttpClient")
            .field("response_limit", &self.response_limit)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AutumnClient for AutumnHttpClient {
    async fn execute(
        &self,
        operation: AutumnOperation,
        request: Value,
        secret_key: &str,
        base_url: &Url,
    ) -> Result<Value, AutumnProviderError> {
        let request =
            normalize_outbound(request, operation.schema_operation()).map_err(|error| {
                AutumnProviderError::internal(format!("Input validation failed: {error}"))
            })?;
        let response = match self
            .http
            .post(operation_url(base_url, operation)?)
            .header(header::AUTHORIZATION, bearer_value(secret_key))
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::USER_AGENT, USER_AGENT)
            .header("x-api-version", "2.3.0")
            .json(&request)
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return transport_failure(operation),
        };
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let body = match bounded_body(response, self.response_limit).await {
            Ok(body) => body,
            Err(()) => return transport_failure(operation),
        };

        if status == StatusCode::OK && is_application_json(&content_type) {
            let value = serde_json::from_slice(&body)
                .map_err(|error| AutumnProviderError::internal(error.to_string()))?;
            return normalize_inbound(value, operation.schema_operation())
                .map_err(|_| response_error(status, &body, "Response validation failed"));
        }

        if operation.fails_open() && status.as_u16() >= 500 {
            return fail_open(operation);
        }

        let fallback = if status.is_client_error() || status.is_server_error() {
            "API error occurred"
        } else {
            "Unexpected Status or Content-Type"
        };
        Err(response_error(
            status,
            &body,
            &default_error_message(fallback, status.as_u16(), &content_type, &body),
        ))
    }
}

fn operation_url(base_url: &Url, operation: AutumnOperation) -> Result<Url, AutumnProviderError> {
    let mut base = base_url.clone();
    if !base.path().ends_with('/') {
        let mut path = base.path().to_owned();
        path.push('/');
        base.set_path(&path);
    }
    base.join(operation.path())
        .map_err(|_| AutumnProviderError::internal("No base URL provided for operation"))
}

fn bearer_value(secret_key: &str) -> String {
    if secret_key
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("bearer "))
    {
        secret_key.to_owned()
    } else {
        format!("Bearer {secret_key}")
    }
}

fn is_application_json(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

async fn bounded_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, ()> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn transport_failure(operation: AutumnOperation) -> Result<Value, AutumnProviderError> {
    if operation.fails_open() {
        fail_open(operation)
    } else {
        Err(AutumnProviderError::response(
            555,
            default_error_message("API error occurred", 555, "", &[]),
            "autumn_api_error",
            "",
        ))
    }
}

fn fail_open(operation: AutumnOperation) -> Result<Value, AutumnProviderError> {
    let body = match operation {
        AutumnOperation::GetOrCreateCustomer => json!({
            "id": null,
            "name": null,
            "email": null,
            "created_at": 0,
            "fingerprint": null,
            "stripe_id": null,
            "env": "live",
            "metadata": {},
            "send_email_receipts": false,
            "billing_controls": {},
            "subscriptions": [],
            "purchases": [],
            "balances": {},
            "flags": {}
        }),
        AutumnOperation::GetEntity => json!({
            "id": null,
            "name": null,
            "customer_id": null,
            "feature_id": null,
            "created_at": 0,
            "env": "live",
            "subscriptions": [],
            "purchases": [],
            "balances": {},
            "flags": {}
        }),
        _ => unreachable!("only fail-open operations reach this function"),
    };
    let encoded = serde_json::to_vec(&body).expect("fail-open fixtures are valid JSON");
    normalize_inbound(body, operation.schema_operation())
        .map_err(|_| response_error(StatusCode::OK, &encoded, "Response validation failed"))
}

fn default_error_message(prefix: &str, status: u16, content_type: &str, body: &[u8]) -> String {
    let content_type = if content_type.is_empty() {
        "\"\"".to_owned()
    } else if content_type.contains(' ') {
        format!("\"{content_type}\"")
    } else {
        content_type.to_owned()
    };
    let body = String::from_utf8_lossy(body);
    let body_length = body.encode_utf16().count();
    let body = if body.is_empty() {
        "\"\"".to_owned()
    } else if body_length > 10_000 {
        let truncated =
            String::from_utf16_lossy(&body.encode_utf16().take(10_000).collect::<Vec<_>>());
        format!("{truncated}...and {} more chars", body_length - 10_000)
    } else {
        body.into_owned()
    };
    let content_type = if content_type == "application/json" {
        String::new()
    } else {
        format!(" Content-Type {content_type}")
    };
    let separator = if body_length > 100 { '\n' } else { ' ' };
    let punctuation = if separator == '\n' { "" } else { "." };
    format!("{prefix}: Status {status}{content_type}{punctuation}{separator}Body: {body}")
        .trim()
        .to_owned()
}

fn response_error(status: StatusCode, body: &[u8], fallback_message: &str) -> AutumnProviderError {
    let value = serde_json::from_slice::<Value>(body).ok();
    let message = value
        .as_ref()
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
        .unwrap_or(fallback_message);
    let code = value
        .as_ref()
        .and_then(|value| value.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("autumn_api_error");
    AutumnProviderError::response(
        status.as_u16(),
        message,
        code,
        String::from_utf8_lossy(body),
    )
}

#[cfg(test)]
#[path = "http/contract.rs"]
mod contract;
