use std::{fmt, sync::Arc};
use url::Url;

const PRODUCTION_URL: &str = "https://api.creem.io";
const TEST_URL: &str = "https://test-api.creem.io";

#[derive(Clone, PartialEq, Eq)]
pub struct CreemProviderConfig {
    pub(crate) api_key: Arc<str>,
    pub base_url: Url,
}

impl CreemProviderConfig {
    pub fn production(api_key: impl Into<String>) -> Self {
        Self::with_base_url(
            api_key,
            Url::parse(PRODUCTION_URL).expect("Creem production URL is valid"),
        )
    }

    pub fn test(api_key: impl Into<String>) -> Self {
        Self::with_base_url(
            api_key,
            Url::parse(TEST_URL).expect("Creem test URL is valid"),
        )
    }

    pub fn with_base_url(api_key: impl Into<String>, base_url: Url) -> Self {
        Self {
            api_key: Arc::from(api_key.into()),
            base_url,
        }
    }
}

impl fmt::Debug for CreemProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreemProviderConfig")
            .field("api_key", &"[REDACTED]")
            .field("base_url", &self.base_url)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CreemProviderError {
    pub status: Option<u16>,
    pub message: String,
    pub(crate) response: Option<Arc<str>>,
}

impl CreemProviderError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            status: None,
            message: message.into(),
            response: None,
        }
    }

    pub(crate) fn response(
        status: u16,
        message: impl Into<String>,
        response: impl Into<String>,
    ) -> Self {
        Self {
            status: Some(status),
            message: message.into(),
            response: Some(response.into().into()),
        }
    }
}

impl fmt::Debug for CreemProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreemProviderError")
            .field("status", &self.status)
            .field("message", &self.message)
            .field("response", &self.response.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl fmt::Display for CreemProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CreemProviderError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_match_the_sdk_and_debug_redacts_secrets() {
        let production = CreemProviderConfig::production("creem_secret");
        assert_eq!(production.base_url.as_str(), "https://api.creem.io/");
        assert!(!format!("{production:?}").contains("creem_secret"));
        assert_eq!(
            CreemProviderConfig::test("secret").base_url.as_str(),
            "https://test-api.creem.io/"
        );
    }

    #[test]
    fn provider_error_debug_redacts_response_bodies() {
        let error = CreemProviderError::response(401, "API error occurred", "secret body");
        let debug = format!("{error:?}");
        assert!(!debug.contains("secret body"));
        assert!(debug.contains("[REDACTED]"));
    }
}
