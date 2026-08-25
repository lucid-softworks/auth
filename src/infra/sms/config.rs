use std::{env, fmt, time::Duration};

const DEFAULT_API_URL: &str = "https://dash.better-auth.com";
const DEFAULT_TIMEOUT_MILLISECONDS: u64 = 3_000;

/// HTTP options accepted by the managed SMS client.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct SmsApiOptions {
    /// Request timeout in milliseconds.
    pub timeout: Option<u64>,
}

impl fmt::Debug for SmsApiOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SmsApiOptions")
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Configuration for Better Auth's managed SMS service.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct SmsConfig {
    /// Better Auth infrastructure bearer credential.
    pub api_key: Option<String>,
    /// Better Auth infrastructure API origin.
    pub api_url: Option<String>,
    /// Preferred HTTP client options.
    pub api_options: Option<SmsApiOptions>,
    /// Deprecated timeout retained by `@better-auth/infra` 0.4.3.
    #[deprecated(note = "use api_options.timeout")]
    pub api_timeout: Option<u64>,
}

impl fmt::Debug for SmsConfig {
    #[allow(deprecated)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SmsConfig")
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("api_url", &self.api_url)
            .field("api_options", &self.api_options)
            .field("api_timeout", &self.api_timeout)
            .finish()
    }
}

pub(super) struct ResolvedSmsConfig {
    pub api_key: String,
    pub api_url: String,
    pub timeout: Duration,
}

impl SmsConfig {
    pub(super) fn resolve(self) -> ResolvedSmsConfig {
        self.resolve_with_env(
            env::var("BETTER_AUTH_API_URL").ok(),
            env::var("BETTER_AUTH_API_KEY").ok(),
        )
    }

    fn resolve_with_env(
        self,
        api_url_env: Option<String>,
        api_key_env: Option<String>,
    ) -> ResolvedSmsConfig {
        let api_url = truthy(self.api_url)
            .or_else(|| truthy(api_url_env))
            .unwrap_or_else(|| DEFAULT_API_URL.to_owned());
        let api_url = if api_url.ends_with("/api") {
            api_url
        } else {
            format!("{api_url}/api")
        };
        let api_key = truthy(self.api_key)
            .or_else(|| truthy(api_key_env))
            .unwrap_or_default();
        #[allow(deprecated)]
        let timeout = self
            .api_options
            .and_then(|options| options.timeout)
            .or(self.api_timeout)
            .unwrap_or(DEFAULT_TIMEOUT_MILLISECONDS);

        ResolvedSmsConfig {
            api_key,
            api_url,
            timeout: Duration::from_millis(timeout),
        }
    }
}

fn truthy(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_the_api_key() {
        #[allow(deprecated)]
        let config = SmsConfig {
            api_key: Some("sms-secret".into()),
            api_url: Some("https://sms.example".into()),
            api_options: None,
            api_timeout: Some(7),
        };

        let debug = format!("{config:?}");
        assert!(!debug.contains("sms-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn timeout_options_override_the_deprecated_timeout_including_zero() {
        #[allow(deprecated)]
        let resolved = SmsConfig {
            api_key: Some("key".into()),
            api_url: Some("https://sms.example/api".into()),
            api_options: Some(SmsApiOptions { timeout: Some(0) }),
            api_timeout: Some(99),
        }
        .resolve();

        assert_eq!(resolved.timeout, Duration::ZERO);
        assert_eq!(resolved.api_url, "https://sms.example/api");
    }

    #[test]
    fn api_suffix_is_appended_without_normalization() {
        let resolved = SmsConfig {
            api_key: Some("key".into()),
            api_url: Some("https://sms.example/api/".into()),
            ..SmsConfig::default()
        }
        .resolve();

        assert_eq!(resolved.api_url, "https://sms.example/api//api");
    }

    #[test]
    fn explicit_values_win_and_empty_values_use_environment_then_defaults() {
        let explicit = SmsConfig {
            api_key: Some("configured-key".into()),
            api_url: Some("https://configured.test".into()),
            ..SmsConfig::default()
        }
        .resolve_with_env(
            Some("https://environment.test".into()),
            Some("environment-key".into()),
        );
        assert_eq!(explicit.api_key, "configured-key");
        assert_eq!(explicit.api_url, "https://configured.test/api");

        let environment = SmsConfig {
            api_key: Some(String::new()),
            api_url: Some(String::new()),
            ..SmsConfig::default()
        }
        .resolve_with_env(
            Some("https://environment.test".into()),
            Some("environment-key".into()),
        );
        assert_eq!(environment.api_key, "environment-key");
        assert_eq!(environment.api_url, "https://environment.test/api");

        let defaults = SmsConfig::default().resolve_with_env(None, None);
        assert!(defaults.api_key.is_empty());
        assert_eq!(defaults.api_url, "https://dash.better-auth.com/api");
        assert_eq!(
            defaults.timeout,
            Duration::from_millis(DEFAULT_TIMEOUT_MILLISECONDS)
        );
    }
}
