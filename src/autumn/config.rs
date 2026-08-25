use super::{AutumnClient, AutumnHttpClient, AutumnIdentityProvider};
use std::{fmt, sync::Arc};
#[cfg(any(feature = "axum", test))]
use url::Url;

#[cfg(any(feature = "axum", test))]
const DEFAULT_AUTUMN_URL: &str = "https://api.useautumn.com";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AutumnCustomerScope {
    #[default]
    User,
    Organization,
    UserAndOrganization,
}

#[derive(Clone)]
pub struct AutumnOptions {
    pub secret_key: Option<String>,
    pub base_url: Option<String>,
    pub autumn_url: Option<String>,
    pub customer_scope: AutumnCustomerScope,
    pub identify: Option<Arc<dyn AutumnIdentityProvider>>,
    pub client: Arc<dyn AutumnClient>,
}

impl Default for AutumnOptions {
    fn default() -> Self {
        Self {
            secret_key: None,
            base_url: None,
            autumn_url: None,
            customer_scope: AutumnCustomerScope::User,
            identify: None,
            client: Arc::new(AutumnHttpClient::default()),
        }
    }
}

impl AutumnOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_client(client: Arc<dyn AutumnClient>) -> Self {
        Self {
            client,
            ..Self::default()
        }
    }

    #[cfg(feature = "axum")]
    pub(crate) fn resolved_secret_key(&self) -> Option<String> {
        self.secret_key
            .as_deref()
            .filter(|secret| !secret.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                std::env::var("AUTUMN_SECRET_KEY")
                    .ok()
                    .filter(|secret| !secret.is_empty())
            })
    }

    #[cfg(any(feature = "axum", test))]
    pub(crate) fn resolved_base_url(&self) -> Result<Url, url::ParseError> {
        let selected = self
            .autumn_url
            .as_deref()
            .or(self.base_url.as_deref())
            .filter(|url| !url.is_empty())
            .unwrap_or(DEFAULT_AUTUMN_URL);
        Url::parse(selected)
    }
}

impl fmt::Debug for AutumnOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AutumnOptions")
            .field(
                "secret_key",
                &self.secret_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("base_url", &self.base_url)
            .field("autumn_url", &self.autumn_url)
            .field("customer_scope", &self.customer_scope)
            .field("has_identify", &self.identify.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autumn_url_has_nullish_precedence_and_empty_uses_sdk_default() {
        let mut options = AutumnOptions {
            base_url: Some("https://example.test/base".into()),
            ..AutumnOptions::default()
        };
        assert_eq!(
            options.resolved_base_url().unwrap().as_str(),
            "https://example.test/base"
        );

        options.autumn_url = Some("https://override.test/prefix".into());
        assert_eq!(
            options.resolved_base_url().unwrap().as_str(),
            "https://override.test/prefix"
        );

        options.autumn_url = Some(String::new());
        assert_eq!(
            options.resolved_base_url().unwrap().as_str(),
            "https://api.useautumn.com/"
        );
    }
}
