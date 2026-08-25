use super::{CreemProviderConfig, CreemProviderError, CreemTransport};
use crate::creem::provider::{
    CreemCheckout, CreemCheckoutRequest, CreemPortal, CreemPortalRequest,
    CreemProviderSubscription, CreemTransactionPage, CreemTransactionSearch, normalize_checkout,
    normalize_portal, normalize_subscription, normalize_transaction_page,
};
use async_trait::async_trait;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Method, StatusCode, header};
use serde_json::{Value, json};
use std::{fmt, time::Duration};
use url::Url;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
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
pub struct CreemHttpTransport {
    http: reqwest::Client,
    config: CreemProviderConfig,
    response_limit: usize,
}

impl CreemHttpTransport {
    pub fn new(config: CreemProviderConfig) -> Self {
        Self::with_limits(config, DEFAULT_TIMEOUT, DEFAULT_RESPONSE_LIMIT)
            .expect("Creem HTTP transport defaults are valid")
    }

    pub fn with_limits(
        config: CreemProviderConfig,
        timeout: Duration,
        response_limit: usize,
    ) -> Result<Self, CreemProviderError> {
        if timeout.is_zero() || response_limit == 0 {
            return Err(CreemProviderError::new(
                "Creem timeout and response limit must be greater than zero",
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| CreemProviderError::new("Unexpected HTTP client error"))?;
        Ok(Self {
            http,
            config,
            response_limit,
        })
    }

    fn url(&self, path: &str) -> Result<Url, CreemProviderError> {
        let mut base = self.config.base_url.clone();
        if !base.path().ends_with('/') {
            let mut base_path = base.path().to_owned();
            base_path.push('/');
            base.set_path(&base_path);
        }
        base.join(path)
            .map_err(|_| CreemProviderError::new("No base URL provided for operation"))
    }

    async fn json(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        query: &[(&str, String)],
    ) -> Result<Value, CreemProviderError> {
        let mut url = self.url(path)?;
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
        let mut request = self
            .http
            .request(method, url)
            .header(header::ACCEPT, "application/json");
        if !self.config.api_key.is_empty() {
            request = request.header("x-api-key", trim_http_whitespace(&self.config.api_key));
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| CreemProviderError::new("Unexpected HTTP client error"))?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let body = bounded_body(response, self.response_limit)
            .await
            .map_err(|_| CreemProviderError::new("Unexpected HTTP client error"))?;
        if status == StatusCode::OK && is_application_json(&content_type) {
            return serde_json::from_slice(&body).map_err(|_| {
                CreemProviderError::response(
                    status.as_u16(),
                    "Response validation failed",
                    String::from_utf8_lossy(&body),
                )
            });
        }
        let message = if status.is_client_error() || status.is_server_error() {
            "API error occurred"
        } else {
            "Unexpected Status or Content-Type"
        };
        Err(CreemProviderError::response(
            status.as_u16(),
            message,
            String::from_utf8_lossy(&body),
        ))
    }
}

impl fmt::Debug for CreemHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreemHttpTransport")
            .field("config", &self.config)
            .field("response_limit", &self.response_limit)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl CreemTransport for CreemHttpTransport {
    fn config(&self) -> &CreemProviderConfig {
        &self.config
    }

    async fn create_checkout(
        &self,
        request: CreemCheckoutRequest,
    ) -> Result<CreemCheckout, CreemProviderError> {
        let body = request.wire_value().map_err(CreemProviderError::new)?;
        let value = self
            .json(Method::POST, "v1/checkouts", Some(&body), &[])
            .await?;
        let (checkout_url, value) = normalize_checkout(value)
            .map_err(|_| CreemProviderError::new("Response validation failed"))?;
        Ok(CreemCheckout {
            checkout_url,
            value,
        })
    }

    async fn create_portal(
        &self,
        request: CreemPortalRequest,
    ) -> Result<CreemPortal, CreemProviderError> {
        let body = serde_json::to_value(request)
            .map_err(|_| CreemProviderError::new("Input validation failed"))?;
        let value = self
            .json(Method::POST, "v1/customers/billing", Some(&body), &[])
            .await?;
        let (customer_portal_link, value) = normalize_portal(value)
            .map_err(|_| CreemProviderError::new("Response validation failed"))?;
        Ok(CreemPortal {
            customer_portal_link,
            value,
        })
    }

    async fn cancel_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<CreemProviderSubscription, CreemProviderError> {
        let path = format!(
            "v1/subscriptions/{}/cancel",
            encode_component(subscription_id)
        );
        let value = self
            .json(Method::POST, &path, Some(&json!({})), &[])
            .await?;
        let value = normalize_subscription(value)
            .map_err(|_| CreemProviderError::new("Response validation failed"))?;
        Ok(CreemProviderSubscription { value })
    }

    async fn retrieve_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<CreemProviderSubscription, CreemProviderError> {
        let query = [("subscription_id", subscription_id.to_owned())];
        let value = self
            .json(Method::GET, "v1/subscriptions", None, &query)
            .await?;
        let value = normalize_subscription(value)
            .map_err(|_| CreemProviderError::new("Response validation failed"))?;
        Ok(CreemProviderSubscription { value })
    }

    async fn search_transactions(
        &self,
        search: CreemTransactionSearch,
    ) -> Result<CreemTransactionPage, CreemProviderError> {
        search.validate().map_err(CreemProviderError::new)?;
        let page = search.page_number();
        let limit = search.page_size();
        let mut query = Vec::with_capacity(5);
        if let Some(customer_id) = search.customer_id {
            query.push(("customer_id", customer_id));
        }
        if let Some(order_id) = search.order_id {
            query.push(("order_id", order_id));
        }
        query.push(("page_number", number(page)));
        query.push(("page_size", number(limit)));
        if let Some(product_id) = search.product_id {
            query.push(("product_id", product_id));
        }
        let value = self
            .json(Method::GET, "v1/transactions/search", None, &query)
            .await?;
        let (value, next_page) = normalize_transaction_page(value, page, limit)
            .map_err(|_| CreemProviderError::new("Response validation failed"))?;
        Ok(CreemTransactionPage { value, next_page })
    }
}

fn number(value: f64) -> String {
    ryu_js::Buffer::new().format(value).to_owned()
}

fn encode_component(value: &str) -> String {
    utf8_percent_encode(value, URI_COMPONENT).to_string()
}

fn trim_http_whitespace(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, ' ' | '\t' | '\r' | '\n'))
}

fn is_application_json(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
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
