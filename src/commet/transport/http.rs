use super::{
    CommetHttpMethod, CommetProviderConfig, CommetProviderError, CommetTransport,
    CommetTransportRequest,
};
use async_trait::async_trait;
use reqwest::{Method, header};
use serde_json::Value;
use std::{fmt, time::Duration};
use url::Url;
use uuid::Uuid;

mod response;
mod retry;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_RETRIES: u32 = 3;
const API_VERSION: &str = "2026-07-31";
const USER_AGENT: &str = concat!("lucid-auth/", env!("CARGO_PKG_VERSION"), " commet/9.1.0");

#[derive(Clone)]
pub struct CommetHttpTransport {
    http: reqwest::Client,
    config: CommetProviderConfig,
    timeout: Duration,
    max_retries: u32,
}

impl CommetHttpTransport {
    pub fn new(config: CommetProviderConfig) -> Self {
        Self::with_timeout_and_retries(config, DEFAULT_TIMEOUT, DEFAULT_MAX_RETRIES)
            .expect("Commet HTTP transport defaults are valid")
    }

    pub fn with_timeout_and_retries(
        config: CommetProviderConfig,
        timeout: Duration,
        max_retries: u32,
    ) -> Result<Self, CommetProviderError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| CommetProviderError::new("Commet HTTP client failed"))?;
        Ok(Self {
            http,
            config,
            timeout,
            max_retries,
        })
    }

    fn url(&self, path: &str, query: &[(String, String)]) -> Result<Url, CommetProviderError> {
        let endpoint = if path.starts_with('/') {
            format!("/api/v1{path}")
        } else {
            format!("/api/v1/{path}")
        };
        let mut url = self
            .config
            .base_url
            .join(&endpoint)
            .map_err(|_| CommetProviderError::new("Commet URL is invalid"))?;
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(key, value)| (&**key, &**value)));
        }
        Ok(url)
    }

    fn idempotency_key(&self, request: &CommetTransportRequest) -> Option<String> {
        request.idempotency_key.clone().or_else(|| {
            (self.max_retries > 0 && request.method.has_body())
                .then(|| format!("commet-node-retry-{}", Uuid::new_v4()))
        })
    }

    async fn execute(
        &self,
        request: &CommetTransportRequest,
        url: &Url,
        idempotency_key: Option<&str>,
    ) -> Result<Value, CommetProviderError> {
        let method = request.method.as_reqwest();
        let mut attempt = 0;
        loop {
            let result = self
                .send_once(request, method.clone(), url.clone(), idempotency_key)
                .await;
            match result {
                Ok((status, headers, value)) if attempt < self.max_retries => {
                    if let Some(delay) = retry::delay(status, &headers, attempt) {
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                    } else if status.is_success() {
                        return Ok(value);
                    } else {
                        return Err(response::api_error(status, value));
                    }
                }
                Ok((status, _, value)) if status.is_success() => return Ok(value),
                Ok((status, _, value)) => return Err(response::api_error(status, value)),
                Err(error) if error.retryable && attempt < self.max_retries => {
                    tokio::time::sleep(retry::network_delay(attempt)).await;
                    attempt += 1;
                }
                Err(error) => return Err(error.error),
            }
        }
    }

    async fn send_once(
        &self,
        request: &CommetTransportRequest,
        method: Method,
        url: Url,
        idempotency_key: Option<&str>,
    ) -> Result<response::ParsedResponse, response::RequestFailure> {
        let mut builder = self
            .http
            .request(method, url)
            .header("x-api-key", trim_http_whitespace(&self.config.api_key))
            .header("commet-version", API_VERSION)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::USER_AGENT, USER_AGENT);
        if let Some(key) = idempotency_key {
            builder = builder.header("Idempotency-Key", trim_http_whitespace(key));
        }
        if let Some(body) = &request.body {
            builder = builder.json(body);
        }
        let response = builder.send().await.map_err(response::request_failure)?;
        response::parse(response).await
    }
}

impl fmt::Debug for CommetHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommetHttpTransport")
            .field("config", &self.config)
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl CommetTransport for CommetHttpTransport {
    async fn send(&self, request: CommetTransportRequest) -> Result<Value, CommetProviderError> {
        let url = self.url(&request.path, &request.query)?;
        let idempotency_key = self.idempotency_key(&request);
        self.execute(&request, &url, idempotency_key.as_deref())
            .await
    }
}

impl CommetHttpMethod {
    fn as_reqwest(self) -> Method {
        match self {
            Self::Get => Method::GET,
            Self::Post => Method::POST,
            Self::Put => Method::PUT,
            Self::Patch => Method::PATCH,
        }
    }

    fn has_body(self) -> bool {
        !matches!(self, Self::Get)
    }
}

fn trim_http_whitespace(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, ' ' | '\t' | '\r' | '\n'))
}

#[cfg(test)]
#[path = "http/contract.rs"]
mod contract;
