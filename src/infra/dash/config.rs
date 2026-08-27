use std::{env, fmt, sync::OnceLock, time::Duration};

const DEFAULT_API_URL: &str = "https://dash.better-auth.com";
const DEFAULT_KV_URL: &str = "https://kv.better-auth.com";
const DEFAULT_API_TIMEOUT_MILLISECONDS: u64 = 3_000;
const DEFAULT_KV_TIMEOUT_MILLISECONDS: u64 = 1_000;
const DEFAULT_KV_RETRY_ATTEMPTS: u32 = 2;
const DEFAULT_KV_RETRY_BASE_DELAY_MILLISECONDS: u64 = 400;
const DEFAULT_KV_RETRY_MAX_DELAY_MILLISECONDS: u64 = 600;

/// Dash API HTTP options.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApiOptions {
    /// Request timeout in milliseconds. Zero disables the client-wide timeout.
    pub timeout: Option<u64>,
}

/// Retry inputs used only by KV identification lookups.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KvRetryOptions {
    /// Maximum retry index after a thrown transport failure.
    pub attempts: Option<u32>,
    /// Delay before the first retry, in milliseconds.
    pub base_delay: Option<u64>,
    /// Maximum exponential delay, in milliseconds.
    pub max_delay: Option<u64>,
}

/// KV HTTP options.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KvOptions {
    /// Request timeout in milliseconds. Zero disables the client-wide timeout.
    pub timeout: Option<u64>,
    /// Identification lookup retry policy.
    pub retry: Option<KvRetryOptions>,
}

/// Shared connection options accepted by Better Auth Infra plugins.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct InfraConnectionOptions {
    /// Better Auth Dash API origin.
    pub api_url: Option<String>,
    /// Better Auth KV origin.
    pub kv_url: Option<String>,
    /// Better Auth Dash credential.
    pub api_key: Option<String>,
    /// Preferred API client options.
    pub api_options: Option<ApiOptions>,
    /// Preferred KV client options.
    pub kv_options: Option<KvOptions>,
    /// Published deprecated API timeout input.
    #[deprecated(note = "use api_options.timeout")]
    pub api_timeout: Option<u64>,
    /// Published deprecated KV timeout input.
    #[deprecated(note = "use kv_options.timeout")]
    pub kv_timeout: Option<u64>,
}

impl fmt::Debug for InfraConnectionOptions {
    #[allow(deprecated)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InfraConnectionOptions")
            .field("api_url", &self.api_url)
            .field("kv_url", &self.kv_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("api_options", &self.api_options)
            .field("kv_options", &self.kv_options)
            .field("api_timeout", &self.api_timeout)
            .field("kv_timeout", &self.kv_timeout)
            .finish()
    }
}

/// Fully resolved shared connection options.
#[derive(Clone, Eq, PartialEq)]
pub struct ResolvedConnectionOptions {
    pub api_url: String,
    pub kv_url: String,
    api_key: String,
    pub api_timeout: Duration,
    pub kv_timeout: Duration,
    pub kv_retry: ResolvedKvRetryOptions,
}

impl fmt::Debug for ResolvedConnectionOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedConnectionOptions")
            .field("api_url", &self.api_url)
            .field("kv_url", &self.kv_url)
            .field("api_key", &"[REDACTED]")
            .field("api_timeout", &self.api_timeout)
            .field("kv_timeout", &self.kv_timeout)
            .field("kv_retry", &self.kv_retry)
            .finish()
    }
}

impl ResolvedConnectionOptions {
    /// Returns the credential for constructing an authenticated managed client.
    ///
    /// Callers should avoid logging or serializing this value.
    pub fn api_key(&self) -> &str {
        &self.api_key
    }
}

/// Resolved KV retry policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedKvRetryOptions {
    pub attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl InfraConnectionOptions {
    pub fn resolve(self) -> ResolvedConnectionOptions {
        self.resolve_with_env(
            Some(module_api_url().to_owned()),
            Some(module_kv_url().to_owned()),
            env::var("BETTER_AUTH_API_KEY").ok(),
        )
    }

    #[allow(deprecated)]
    fn resolve_with_env(
        self,
        api_url_env: Option<String>,
        kv_url_env: Option<String>,
        api_key_env: Option<String>,
    ) -> ResolvedConnectionOptions {
        let api_url = truthy(self.api_url)
            .or_else(|| truthy(api_url_env))
            .unwrap_or_else(|| DEFAULT_API_URL.to_owned());
        let kv_url = truthy(self.kv_url)
            .or_else(|| truthy(kv_url_env))
            .unwrap_or_else(|| DEFAULT_KV_URL.to_owned());
        let api_key = truthy(self.api_key)
            .or_else(|| truthy(api_key_env))
            .unwrap_or_default();
        let api_timeout = self
            .api_options
            .and_then(|options| options.timeout)
            .or(self.api_timeout)
            .unwrap_or(DEFAULT_API_TIMEOUT_MILLISECONDS);
        let kv_options = self.kv_options.unwrap_or_default();
        let kv_timeout = kv_options
            .timeout
            .or(self.kv_timeout)
            .unwrap_or(DEFAULT_KV_TIMEOUT_MILLISECONDS);
        let retry = kv_options.retry.unwrap_or_default();

        ResolvedConnectionOptions {
            api_url,
            kv_url,
            api_key,
            api_timeout: Duration::from_millis(api_timeout),
            kv_timeout: Duration::from_millis(kv_timeout),
            kv_retry: ResolvedKvRetryOptions {
                attempts: retry.attempts.unwrap_or(DEFAULT_KV_RETRY_ATTEMPTS),
                base_delay: Duration::from_millis(
                    retry
                        .base_delay
                        .unwrap_or(DEFAULT_KV_RETRY_BASE_DELAY_MILLISECONDS),
                ),
                max_delay: Duration::from_millis(
                    retry
                        .max_delay
                        .unwrap_or(DEFAULT_KV_RETRY_MAX_DELAY_MILLISECONDS),
                ),
            },
        }
    }
}

fn truthy(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn module_api_url() -> &'static str {
    static VALUE: OnceLock<String> = OnceLock::new();
    VALUE
        .get_or_init(|| {
            env::var("BETTER_AUTH_API_URL")
                .ok()
                .and_then(|value| truthy(Some(value)))
                .unwrap_or_else(|| DEFAULT_API_URL.to_owned())
        })
        .as_str()
}

fn module_kv_url() -> &'static str {
    static VALUE: OnceLock<String> = OnceLock::new();
    VALUE
        .get_or_init(|| {
            env::var("BETTER_AUTH_KV_URL")
                .ok()
                .and_then(|value| truthy(Some(value)))
                .unwrap_or_else(|| DEFAULT_KV_URL.to_owned())
        })
        .as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_exact_falsey_and_nullish_precedence() {
        #[allow(deprecated)]
        let resolved = InfraConnectionOptions {
            api_url: Some(String::new()),
            kv_url: Some(String::new()),
            api_key: Some(String::new()),
            api_options: Some(ApiOptions { timeout: Some(0) }),
            kv_options: Some(KvOptions {
                timeout: Some(0),
                retry: Some(KvRetryOptions {
                    attempts: Some(0),
                    base_delay: Some(0),
                    max_delay: Some(0),
                }),
            }),
            api_timeout: Some(9),
            kv_timeout: Some(8),
        }
        .resolve_with_env(
            Some("https://api.env.test".into()),
            Some("https://kv.env.test".into()),
            Some("env-secret".into()),
        );

        assert_eq!(resolved.api_url, "https://api.env.test");
        assert_eq!(resolved.kv_url, "https://kv.env.test");
        assert_eq!(resolved.api_key(), "env-secret");
        assert_eq!(resolved.api_timeout, Duration::ZERO);
        assert_eq!(resolved.kv_timeout, Duration::ZERO);
        assert_eq!(resolved.kv_retry.attempts, 0);
        assert_eq!(resolved.kv_retry.base_delay, Duration::ZERO);
        assert_eq!(resolved.kv_retry.max_delay, Duration::ZERO);
    }

    #[test]
    fn defaults_match_the_published_artifact() {
        let resolved = InfraConnectionOptions::default().resolve_with_env(None, None, None);
        assert_eq!(resolved.api_url, DEFAULT_API_URL);
        assert_eq!(resolved.kv_url, DEFAULT_KV_URL);
        assert_eq!(resolved.api_key(), "");
        assert_eq!(resolved.api_timeout, Duration::from_millis(3_000));
        assert_eq!(resolved.kv_timeout, Duration::from_millis(1_000));
        assert_eq!(resolved.kv_retry.attempts, 2);
        assert_eq!(resolved.kv_retry.base_delay, Duration::from_millis(400));
        assert_eq!(resolved.kv_retry.max_delay, Duration::from_millis(600));
    }

    #[test]
    fn debug_redacts_credentials() {
        let options = InfraConnectionOptions {
            api_key: Some("managed-secret".into()),
            ..InfraConnectionOptions::default()
        };
        let debug = format!("{options:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("managed-secret"));
    }
}
