use crate::PluginApiError;
use serde_json::Value;
use std::{fmt, sync::Arc};
use url::Url;

#[derive(Clone, PartialEq, Eq)]
pub struct CommetProviderConfig {
    pub(crate) api_key: Arc<str>,
    pub base_url: Url,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommetHttpMethod {
    Get,
    Post,
    Put,
    Patch,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CommetTransportRequest {
    pub method: CommetHttpMethod,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Option<Value>,
    pub idempotency_key: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub enum CommetProviderError {
    Api(PluginApiError),
    Opaque,
    Failure {
        status: Option<u16>,
        message: String,
        response: Option<Arc<str>>,
    },
}

impl CommetProviderError {
    pub fn new(message: impl Into<String>) -> Self {
        Self::Failure {
            status: None,
            message: message.into(),
            response: None,
        }
    }

    pub fn api(error: PluginApiError) -> Self {
        Self::Api(error)
    }

    pub fn opaque() -> Self {
        Self::Opaque
    }

    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Api(error) => Some(error.status),
            Self::Opaque => None,
            Self::Failure { status, .. } => *status,
        }
    }

    pub(crate) fn response(
        status: u16,
        message: impl Into<String>,
        response: impl Into<String>,
    ) -> Self {
        Self::Failure {
            status: Some(status),
            message: message.into(),
            response: Some(Arc::from(response.into())),
        }
    }

    pub fn into_api_error(self) -> Result<PluginApiError, Self> {
        match self {
            Self::Api(error) => Ok(error),
            error => Err(error),
        }
    }
}

impl fmt::Debug for CommetProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api(error) => formatter.debug_tuple("Api").field(error).finish(),
            Self::Opaque => formatter.write_str("Opaque"),
            Self::Failure {
                status,
                message,
                response,
            } => formatter
                .debug_struct("Failure")
                .field("status", status)
                .field("message", message)
                .field("response", &response.as_ref().map(|_| "[REDACTED]"))
                .finish(),
        }
    }
}

impl fmt::Display for CommetProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api(error) => error.fmt(formatter),
            Self::Opaque => formatter.write_str("Commet provider failure"),
            Self::Failure { message, .. } => formatter.write_str(message),
        }
    }
}

impl std::error::Error for CommetProviderError {}

const BASE_URL: &str = "https://commet.co";

impl CommetProviderConfig {
    pub fn new(api_key: impl Into<String>) -> Result<Self, CommetProviderError> {
        Self::with_base_url(
            api_key,
            Url::parse(BASE_URL).expect("Commet production URL is valid"),
        )
    }

    pub fn with_base_url(
        api_key: impl Into<String>,
        base_url: Url,
    ) -> Result<Self, CommetProviderError> {
        let api_key = api_key.into();
        if api_key.is_empty() {
            return Err(CommetProviderError::new("Commet SDK: API key is required"));
        }
        if !api_key.starts_with("ck_") {
            return Err(CommetProviderError::new(
                "Commet SDK: Invalid API key format. Expected format: ck_xxx...",
            ));
        }
        Ok(Self {
            api_key: Arc::from(api_key),
            base_url,
        })
    }
}

impl fmt::Debug for CommetProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommetProviderConfig")
            .field("api_key", &"[REDACTED]")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl CommetTransportRequest {
    pub fn get(path: impl Into<String>, query: Vec<(String, String)>) -> Self {
        Self::new(CommetHttpMethod::Get, path, query, None)
    }

    pub fn post(path: impl Into<String>, body: Value) -> Self {
        Self::new(CommetHttpMethod::Post, path, Vec::new(), Some(body))
    }

    pub fn put(path: impl Into<String>, body: Value) -> Self {
        Self::new(CommetHttpMethod::Put, path, Vec::new(), Some(body))
    }

    pub fn patch(path: impl Into<String>, body: Value) -> Self {
        Self::new(CommetHttpMethod::Patch, path, Vec::new(), Some(body))
    }

    pub fn with_idempotency_key(mut self, key: Option<&str>) -> Self {
        self.idempotency_key = key.filter(|key| !key.is_empty()).map(str::to_owned);
        self
    }

    fn new(
        method: CommetHttpMethod,
        path: impl Into<String>,
        query: Vec<(String, String)>,
        body: Option<Value>,
    ) -> Self {
        Self {
            method,
            path: path.into(),
            query,
            body,
            idempotency_key: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_api_keys_and_provider_bodies() {
        let config = CommetProviderConfig::new("ck_commet_sensitive").unwrap();
        assert_eq!(config.base_url.as_str(), "https://commet.co/");
        assert!(!format!("{config:?}").contains("commet_sensitive"));

        let error = CommetProviderError::response(401, "Unauthorized", "provider secret");
        assert_eq!(error.status(), Some(401));
        assert_eq!(error.to_string(), "Unauthorized");
        assert!(!format!("{error:?}").contains("provider secret"));
    }

    #[test]
    fn api_key_validation_uses_the_original_untrimmed_sdk_input() {
        assert_eq!(
            CommetProviderConfig::new("").unwrap_err().to_string(),
            "Commet SDK: API key is required"
        );
        for invalid in ["key", " ck_valid"] {
            assert_eq!(
                CommetProviderConfig::new(invalid).unwrap_err().to_string(),
                "Commet SDK: Invalid API key format. Expected format: ck_xxx..."
            );
        }
        assert!(CommetProviderConfig::new("ck_valid\n").is_ok());
    }

    #[test]
    fn api_errors_can_be_distinguished_without_downcasting() {
        let api = PluginApiError::new(400, "BAD_REQUEST", "exact message");
        assert_eq!(
            CommetProviderError::api(api.clone()).into_api_error(),
            Ok(api)
        );
        assert!(
            CommetProviderError::new("offline")
                .into_api_error()
                .is_err()
        );
        assert_eq!(CommetProviderError::opaque().status(), None);
        assert_eq!(
            CommetProviderError::opaque().to_string(),
            "Commet provider failure"
        );
    }
}
