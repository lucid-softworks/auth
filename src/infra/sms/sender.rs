use super::{SendSmsOptions, SendSmsResult, SmsConfig};
use reqwest::header;
use serde_json::{Map, Value};
use std::{fmt, sync::Arc, time::Duration};

#[path = "sender/transport.rs"]
mod transport;

use transport::{RequestFailure, execute};

const USER_AGENT: &str = "@better-auth/infra v0.4.3";
const CLIENT_IP_HEADER: &str = "x-better-auth-client-ip";
const FAILED_TO_PARSE_JSON: &str = "Failed to parse JSON";

/// Reusable client for Better Auth's managed SMS service.
#[derive(Clone)]
pub struct SmsSender {
    http: reqwest::Client,
    api_key: Arc<str>,
    api_url: Arc<str>,
    timeout: Duration,
}

impl SmsSender {
    pub fn new(config: Option<SmsConfig>) -> Self {
        let resolved = config.unwrap_or_default().resolve();
        if resolved.api_key.is_empty() {
            tracing::warn!(
                "[Dash] No API key provided for SMS sending. Set BETTER_AUTH_API_KEY environment variable or pass apiKey in config."
            );
        }
        let builder = if resolved.timeout.is_zero() {
            reqwest::Client::builder()
        } else {
            reqwest::Client::builder().timeout(resolved.timeout)
        };
        let http = builder
            .build()
            .expect("managed SMS HTTP client configuration is valid");
        Self {
            http,
            api_key: Arc::from(resolved.api_key),
            api_url: Arc::from(resolved.api_url),
            timeout: resolved.timeout,
        }
    }

    /// Send one SMS. No request is made when the API key is missing.
    pub async fn send(&self, options: SendSmsOptions) -> SendSmsResult {
        if self.api_key.is_empty() {
            return SendSmsResult::failure("API key not configured");
        }

        let body = sms_body(&options);
        let mut request = self
            .http
            .post(operation_url(&self.api_url, "/v1/sms/send"))
            .header(header::AUTHORIZATION, format!("Bearer {}", self.api_key))
            .header(header::USER_AGENT, USER_AGENT)
            .json(&body);
        if let Some(client_ip) = options.client_ip.filter(|value| !value.is_empty()) {
            request = request.header(CLIENT_IP_HEADER, client_ip);
        }

        let value = match execute(request).await {
            Ok(value) => value,
            Err(RequestFailure::Http(error)) => return SendSmsResult::failure(error),
            Err(RequestFailure::Exception(error)) => {
                tracing::warn!("[Dash] SMS send failed: {error}");
                return SendSmsResult::failure(error);
            }
        };
        let Value::Object(object) = value else {
            return SendSmsResult::failure(FAILED_TO_PARSE_JSON);
        };
        SendSmsResult::success(object.get("messageId").cloned())
    }
}

impl Default for SmsSender {
    fn default() -> Self {
        Self::new(None)
    }
}

impl fmt::Debug for SmsSender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SmsSender")
            .field("api_key", &"[REDACTED]")
            .field("api_url", &"[CONFIGURED]")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

pub fn create_sms_sender(config: Option<SmsConfig>) -> SmsSender {
    SmsSender::new(config)
}

pub async fn send_sms(options: SendSmsOptions, config: Option<SmsConfig>) -> SendSmsResult {
    create_sms_sender(config).send(options).await
}

fn sms_body(options: &SendSmsOptions) -> Value {
    let mut object = Map::new();
    object.insert("to".into(), Value::String(options.to.clone()));
    object.insert("code".into(), Value::String(options.code.clone()));
    if let Some(template) = options.template {
        object.insert(
            "template".into(),
            serde_json::to_value(template).expect("SMS template identifiers are serializable"),
        );
    }
    Value::Object(object)
}

fn operation_url(base_url: &str, path: &str) -> String {
    let base_url = if base_url.ends_with('/') {
        base_url.to_owned()
    } else {
        format!("{base_url}/")
    };
    url::Url::parse(&base_url)
        .and_then(|base_url| base_url.join(path.trim_start_matches('/')))
        .map_or_else(
            |_| format!("{base_url}{}", path.trim_start_matches('/')),
            |url| url.into(),
        )
}

#[cfg(test)]
#[path = "sender/contract.rs"]
mod contract;
#[cfg(test)]
#[path = "sender/response_contract.rs"]
mod response_contract;
