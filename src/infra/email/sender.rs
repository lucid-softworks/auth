use super::{
    BulkEmailRecipient, EmailConfig, EmailTemplate, EmailTemplateId, EmailTemplateVariables,
    SendBulkEmailsOptions, SendBulkEmailsResult, SendEmailOptions, SendEmailResult,
};
use reqwest::header;
use serde_json::{Map, Value};
use std::{fmt, sync::Arc, time::Duration};

#[path = "sender/transport.rs"]
mod transport;

use transport::{RequestFailure, execute};

const USER_AGENT: &str = "@better-auth/infra v0.4.3";
const FAILED_TO_PARSE_JSON: &str = "Failed to parse JSON";

/// Reusable client for Better Auth's managed email service.
#[derive(Clone)]
pub struct EmailSender {
    http: reqwest::Client,
    api_key: Arc<str>,
    api_url: Arc<str>,
    timeout: Duration,
}

impl EmailSender {
    pub fn new(config: Option<EmailConfig>) -> Self {
        let resolved = config.unwrap_or_default().resolve();
        if resolved.api_key.is_empty() {
            tracing::warn!(
                "[Dash] No API key provided for email sending. Set BETTER_AUTH_API_KEY environment variable or pass apiKey in config."
            );
        }
        let builder = if resolved.timeout.is_zero() {
            reqwest::Client::builder()
        } else {
            reqwest::Client::builder().timeout(resolved.timeout)
        };
        let http = builder
            .build()
            .expect("managed email HTTP client configuration is valid");
        Self {
            http,
            api_key: Arc::from(resolved.api_key),
            api_url: Arc::from(resolved.api_url),
            timeout: resolved.timeout,
        }
    }

    /// Send one email. No request is made when the API key is missing.
    pub async fn send<V>(&self, options: SendEmailOptions<V>) -> SendEmailResult
    where
        V: EmailTemplateVariables,
    {
        if self.api_key.is_empty() {
            return SendEmailResult::failure("API key not configured");
        }

        let body = match single_body(&options) {
            Ok(body) => body,
            Err(error) => return SendEmailResult::failure(error),
        };
        let value = match self.post("/v1/email/send", body).await {
            Ok(value) => value,
            Err(RequestFailure::Http(error)) => return SendEmailResult::failure(error),
            Err(RequestFailure::Exception(error)) => {
                tracing::warn!("[Dash] Email send failed: {error}");
                return SendEmailResult::failure(error);
            }
        };
        match value {
            Value::Object(object) => SendEmailResult::success(object.get("messageId").cloned()),
            Value::Null => {
                let error = "Cannot read properties of null (reading 'messageId')";
                tracing::warn!("[Dash] Email send failed: {error}");
                SendEmailResult::failure(error)
            }
            _ => SendEmailResult::failure(FAILED_TO_PARSE_JSON),
        }
    }

    /// Send one bulk request. The managed client never fans out or retries.
    pub async fn send_bulk<V>(&self, options: SendBulkEmailsOptions<V>) -> SendBulkEmailsResult
    where
        V: EmailTemplateVariables,
    {
        if self.api_key.is_empty() {
            return SendBulkEmailsResult::failure_for(&options.emails, "API key not configured");
        }

        let body = match bulk_body(&options) {
            Ok(body) => body,
            Err(error) => return SendBulkEmailsResult::failure_for(&options.emails, error),
        };
        let value = match self.post("/v1/email/send-bulk", body).await {
            Ok(value) => value,
            Err(RequestFailure::Http(error)) => {
                return SendBulkEmailsResult::failure_for(&options.emails, error);
            }
            Err(RequestFailure::Exception(error)) => {
                tracing::warn!("[Dash] Bulk email send failed: {error}");
                return SendBulkEmailsResult::failure_for(&options.emails, error);
            }
        };
        if value.is_null() {
            let error = "Cannot read properties of null (reading 'success')";
            tracing::warn!("[Dash] Bulk email send failed: {error}");
            return SendBulkEmailsResult::failure_for(&options.emails, error);
        }
        let Value::Object(object) = value else {
            return SendBulkEmailsResult::failure_for(&options.emails, FAILED_TO_PARSE_JSON);
        };
        let Some(success) = object.get("success").and_then(Value::as_bool) else {
            return SendBulkEmailsResult::failure_for(&options.emails, FAILED_TO_PARSE_JSON);
        };
        SendBulkEmailsResult::from_response(success, object.get("failures").cloned())
    }

    /// Return any top-level response array without validating its members.
    pub async fn get_templates(&self) -> Vec<EmailTemplate> {
        if self.api_key.is_empty() {
            return Vec::new();
        }

        match self.get("/v1/email/templates").await {
            Ok(Value::Array(templates)) => templates,
            Err(RequestFailure::Exception(error)) => {
                tracing::warn!("[Dash] Failed to fetch email templates: {error}");
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value, RequestFailure> {
        execute(
            self.http
                .post(operation_url(&self.api_url, path))
                .header(header::AUTHORIZATION, format!("Bearer {}", self.api_key))
                .header(header::USER_AGENT, USER_AGENT)
                .json(&body),
        )
        .await
    }

    async fn get(&self, path: &str) -> Result<Value, RequestFailure> {
        execute(
            self.http
                .get(operation_url(&self.api_url, path))
                .header(header::AUTHORIZATION, format!("Bearer {}", self.api_key))
                .header(header::USER_AGENT, USER_AGENT),
        )
        .await
    }
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

impl Default for EmailSender {
    fn default() -> Self {
        Self::new(None)
    }
}

impl fmt::Debug for EmailSender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailSender")
            .field("api_key", &"[REDACTED]")
            .field("api_url", &"[CONFIGURED]")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

pub fn create_email_sender(config: Option<EmailConfig>) -> EmailSender {
    EmailSender::new(config)
}

pub async fn send_email<V>(
    options: SendEmailOptions<V>,
    config: Option<EmailConfig>,
) -> SendEmailResult
where
    V: EmailTemplateVariables,
{
    create_email_sender(config).send(options).await
}

pub async fn send_bulk_emails<V>(
    options: SendBulkEmailsOptions<V>,
    config: Option<EmailConfig>,
) -> SendBulkEmailsResult
where
    V: EmailTemplateVariables,
{
    create_email_sender(config).send_bulk(options).await
}

fn single_body<V>(options: &SendEmailOptions<V>) -> Result<Value, String>
where
    V: EmailTemplateVariables,
{
    let mut object = Map::new();
    object.insert("template".into(), template_value(V::TEMPLATE));
    object.insert("to".into(), Value::String(options.to.clone()));
    object.insert(
        "variables".into(),
        serde_json::to_value(&options.variables).map_err(|error| error.to_string())?,
    );
    if let Some(subject) = &options.subject {
        object.insert("subject".into(), Value::String(subject.clone()));
    }
    Ok(Value::Object(object))
}

fn bulk_body<V>(options: &SendBulkEmailsOptions<V>) -> Result<Value, String>
where
    V: EmailTemplateVariables,
{
    let emails = options
        .emails
        .iter()
        .map(bulk_recipient)
        .collect::<Result<Vec<_>, _>>()?;
    let mut object = Map::new();
    object.insert("template".into(), template_value(V::TEMPLATE));
    object.insert("emails".into(), Value::Array(emails));
    if let Some(subject) = &options.subject {
        object.insert("subject".into(), Value::String(subject.clone()));
    }
    object.insert(
        "variables".into(),
        serde_json::to_value(&options.variables).map_err(|error| error.to_string())?,
    );
    Ok(Value::Object(object))
}

fn bulk_recipient<V>(recipient: &BulkEmailRecipient<V>) -> Result<Value, String>
where
    V: EmailTemplateVariables,
{
    let variables = recipient
        .variables
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or_else(|| Value::Object(Map::new()));
    Ok(serde_json::json!({
        "to": recipient.to,
        "variables": variables
    }))
}

fn template_value(template: EmailTemplateId) -> Value {
    serde_json::to_value(template).expect("email template identifiers are serializable")
}

#[cfg(test)]
#[path = "sender/contract.rs"]
mod contract;
#[cfg(test)]
#[path = "sender/response_contract.rs"]
mod response_contract;
