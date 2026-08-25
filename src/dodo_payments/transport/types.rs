use serde_json::Value;
use std::{fmt, sync::Arc};
use url::Url;

const LIVE_URL: &str = "https://live.dodopayments.com";
const TEST_URL: &str = "https://test.dodopayments.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DodoPaymentsEnvironment {
    Live,
    Test,
}

#[derive(Clone, PartialEq, Eq)]
pub struct DodoPaymentsProviderConfig {
    pub(crate) api_key: Arc<str>,
    pub environment: DodoPaymentsEnvironment,
    pub base_url: Url,
}

impl DodoPaymentsProviderConfig {
    pub fn live(api_key: impl Into<String>) -> Self {
        Self::with_base_url(
            api_key,
            DodoPaymentsEnvironment::Live,
            Url::parse(LIVE_URL).expect("Dodo Payments live URL is valid"),
        )
    }

    pub fn test(api_key: impl Into<String>) -> Self {
        Self::with_base_url(
            api_key,
            DodoPaymentsEnvironment::Test,
            Url::parse(TEST_URL).expect("Dodo Payments test URL is valid"),
        )
    }

    pub fn with_base_url(
        api_key: impl Into<String>,
        environment: DodoPaymentsEnvironment,
        base_url: Url,
    ) -> Self {
        Self {
            api_key: Arc::from(api_key.into()),
            environment,
            base_url,
        }
    }
}

impl fmt::Debug for DodoPaymentsProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DodoPaymentsProviderConfig")
            .field("api_key", &"[REDACTED]")
            .field("environment", &self.environment)
            .field("base_url", &self.base_url)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DodoPaymentsHttpMethod {
    Get,
    Post,
    Patch,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DodoPaymentsTransportRequest {
    pub method: DodoPaymentsHttpMethod,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Option<Value>,
    pub idempotency_key: Option<String>,
}

impl DodoPaymentsTransportRequest {
    pub fn get(path: impl Into<String>, query: Vec<(String, String)>) -> Self {
        Self {
            method: DodoPaymentsHttpMethod::Get,
            path: path.into(),
            query,
            body: None,
            idempotency_key: None,
        }
    }

    pub fn post(path: impl Into<String>, body: Value) -> Self {
        Self {
            method: DodoPaymentsHttpMethod::Post,
            path: path.into(),
            query: Vec::new(),
            body: Some(body),
            idempotency_key: None,
        }
    }

    pub fn post_empty(path: impl Into<String>) -> Self {
        Self {
            method: DodoPaymentsHttpMethod::Post,
            path: path.into(),
            query: Vec::new(),
            body: None,
            idempotency_key: None,
        }
    }

    pub fn patch(path: impl Into<String>, body: Value) -> Self {
        Self {
            method: DodoPaymentsHttpMethod::Patch,
            path: path.into(),
            query: Vec::new(),
            body: Some(body),
            idempotency_key: None,
        }
    }

    pub fn with_idempotency_key(mut self, key: Option<&str>) -> Self {
        self.idempotency_key = key.map(str::to_owned);
        self
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DodoPaymentsProviderError {
    status: Option<u16>,
    message: String,
    response: Option<Arc<str>>,
}

impl DodoPaymentsProviderError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            status: None,
            message: message.into(),
            response: None,
        }
    }

    pub fn status(&self) -> Option<u16> {
        self.status
    }

    pub(crate) fn response(status: u16, response: impl Into<String>) -> Self {
        Self {
            status: Some(status),
            message: "Dodo Payments API request failed".into(),
            response: Some(Arc::from(response.into())),
        }
    }
}

impl fmt::Debug for DodoPaymentsProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DodoPaymentsProviderError")
            .field("status", &self.status)
            .field("message", &self.message)
            .field("response", &self.response.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl fmt::Display for DodoPaymentsProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for DodoPaymentsProviderError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environments_match_sdk_origins_and_debug_redacts_api_keys() {
        let live = DodoPaymentsProviderConfig::live("live_sensitive");
        assert_eq!(live.base_url.as_str(), "https://live.dodopayments.com/");
        assert_eq!(live.environment, DodoPaymentsEnvironment::Live);
        assert!(!format!("{live:?}").contains("live_sensitive"));

        let test = DodoPaymentsProviderConfig::test("test_sensitive");
        assert_eq!(test.base_url.as_str(), "https://test.dodopayments.com/");
        assert_eq!(test.environment, DodoPaymentsEnvironment::Test);
    }

    #[test]
    fn provider_errors_do_not_expose_response_bodies() {
        let error = DodoPaymentsProviderError::response(401, "customer secret");
        assert_eq!(error.status(), Some(401));
        assert!(!format!("{error:?}").contains("customer secret"));
        assert!(!error.to_string().contains("customer secret"));
    }
}
