use super::{
    DodoPaymentsEnvironment, DodoPaymentsHttpMethod, DodoPaymentsProviderConfig,
    DodoPaymentsProviderError, DodoPaymentsTransport, DodoPaymentsTransportRequest,
};
use async_trait::async_trait;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Method, header};
use serde_json::Value;
use std::{fmt, time::Duration};
use url::Url;

mod retry;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
const DEFAULT_MAX_RETRIES: u32 = 2;
const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

#[derive(Clone)]
pub struct DodoPaymentsHttpTransport {
    http: reqwest::Client,
    config: DodoPaymentsProviderConfig,
    timeout: Duration,
    response_limit: usize,
    max_retries: u32,
}

impl DodoPaymentsHttpTransport {
    pub fn new(config: DodoPaymentsProviderConfig) -> Self {
        Self::with_limits(config, DEFAULT_TIMEOUT, DEFAULT_RESPONSE_LIMIT)
            .expect("Dodo Payments HTTP transport defaults are valid")
    }

    pub fn with_limits(
        config: DodoPaymentsProviderConfig,
        timeout: Duration,
        response_limit: usize,
    ) -> Result<Self, DodoPaymentsProviderError> {
        Self::with_limits_and_retries(config, timeout, response_limit, DEFAULT_MAX_RETRIES)
    }

    pub fn with_limits_and_retries(
        config: DodoPaymentsProviderConfig,
        timeout: Duration,
        response_limit: usize,
        max_retries: u32,
    ) -> Result<Self, DodoPaymentsProviderError> {
        if timeout.is_zero() || response_limit == 0 {
            return Err(DodoPaymentsProviderError::new(
                "Dodo Payments timeout and response limit must be greater than zero",
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| DodoPaymentsProviderError::new("Dodo Payments HTTP client failed"))?;
        Ok(Self {
            http,
            config,
            timeout,
            response_limit,
            max_retries,
        })
    }

    fn url(
        &self,
        path: &str,
        query: &[(String, String)],
    ) -> Result<Url, DodoPaymentsProviderError> {
        let mut base = self.config.base_url.clone();
        if !base.path().ends_with('/') {
            let mut path = base.path().to_owned();
            path.push('/');
            base.set_path(&path);
        }
        let mut url = base
            .join(path)
            .map_err(|_| DodoPaymentsProviderError::new("Dodo Payments URL is invalid"))?;
        if !query.is_empty() {
            url.set_query(Some(
                &query
                    .iter()
                    .map(|(key, value)| {
                        format!("{}={}", encode_component(key), encode_component(value))
                    })
                    .collect::<Vec<_>>()
                    .join("&"),
            ));
        }
        Ok(url)
    }
}

impl fmt::Debug for DodoPaymentsHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DodoPaymentsHttpTransport")
            .field("config", &self.config)
            .field("timeout", &self.timeout)
            .field("response_limit", &self.response_limit)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DodoPaymentsTransport for DodoPaymentsHttpTransport {
    fn environment(&self) -> DodoPaymentsEnvironment {
        self.config.environment
    }

    async fn send(
        &self,
        request: DodoPaymentsTransportRequest,
    ) -> Result<Value, DodoPaymentsProviderError> {
        let url = self.url(&request.path, &request.query)?;
        let method = match request.method {
            DodoPaymentsHttpMethod::Get => Method::GET,
            DodoPaymentsHttpMethod::Post => Method::POST,
            DodoPaymentsHttpMethod::Patch => Method::PATCH,
        };
        let mut retry_count = 0;
        let response = loop {
            let mut builder = self
                .http
                .request(method.clone(), url.clone())
                .header(header::ACCEPT, "application/json")
                .header(header::USER_AGENT, "DodoPayments/JS 2.47.0")
                .header("X-Stainless-Retry-Count", retry_count.to_string())
                .header("X-Stainless-Timeout", self.timeout.as_secs().to_string())
                .header("X-Stainless-Lang", "rust")
                .header("X-Stainless-Package-Version", "2.47.0")
                .header("X-Stainless-OS", stainless_os())
                .header("X-Stainless-Arch", stainless_arch())
                .header("X-Stainless-Runtime", "unknown")
                .header("X-Stainless-Runtime-Version", "unknown")
                .bearer_auth(trim_http_whitespace(&self.config.api_key));
            // The pinned SDK accepts `idempotencyKey` but never configures its
            // optional idempotency header, so the key is intentionally not sent.
            if let Some(body) = &request.body {
                builder = builder.json(body);
            }
            match builder.send().await {
                Ok(response)
                    if retry_count < self.max_retries
                        && retry::should_retry(response.status(), response.headers()) =>
                {
                    let delay = retry::delay(
                        Some(response.headers()),
                        retry_count,
                        rand::random(),
                        chrono::Utc::now(),
                    );
                    tokio::time::sleep(delay).await;
                    retry_count += 1;
                }
                Ok(response) => break response,
                Err(_) if retry_count < self.max_retries => {
                    let delay = retry::delay(None, retry_count, rand::random(), chrono::Utc::now());
                    tokio::time::sleep(delay).await;
                    retry_count += 1;
                }
                Err(error) => {
                    let message = if error.is_timeout() {
                        "Dodo Payments HTTP request timed out"
                    } else {
                        "Dodo Payments HTTP request failed"
                    };
                    return Err(DodoPaymentsProviderError::new(message));
                }
            }
        };
        let status = response.status();
        let body = bounded_body(response, self.response_limit)
            .await
            .map_err(|_| DodoPaymentsProviderError::new("Dodo Payments response exceeded limit"))?;
        if status.is_success() {
            return serde_json::from_slice(&body).map_err(|_| {
                DodoPaymentsProviderError::new("Dodo Payments response validation failed")
            });
        }
        Err(DodoPaymentsProviderError::response(
            status.as_u16(),
            String::from_utf8_lossy(&body),
        ))
    }
}

fn stainless_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "MacOS",
        "linux" => "Linux",
        "windows" => "Windows",
        "freebsd" => "FreeBSD",
        "openbsd" => "OpenBSD",
        "ios" => "iOS",
        "android" => "Android",
        _ => "Unknown",
    }
}

fn stainless_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86" => "x32",
        "x86_64" => "x64",
        "arm" => "arm",
        "aarch64" => "arm64",
        _ => "unknown",
    }
}

fn encode_component(value: &str) -> String {
    utf8_percent_encode(value, URI_COMPONENT).to_string()
}

fn trim_http_whitespace(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, ' ' | '\t' | '\r' | '\n'))
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

#[cfg(test)]
#[path = "http/contract.rs"]
mod contract;
