use crate::{AuthError, PluginRateLimit};
use async_trait::async_trait;
use std::{collections::BTreeMap, sync::Arc};

mod storage;

pub(crate) use storage::{RateLimiter, duration, retry_after};

/// Better Auth request limit expressed in seconds and requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitRule {
    pub window: u64,
    pub max: u32,
}

impl RateLimitRule {
    pub const fn new(window: u64, max: u32) -> Self {
        Self { window, max }
    }
}

/// Static Better Auth `customRules` entry. `None` disables limiting for the
/// matching path, and `*` wildcards follow Better Auth's path matching.
#[derive(Clone)]
pub struct RateLimitCustomRule {
    path: String,
    policy: RateLimitCustomPolicy,
}

#[derive(Clone)]
enum RateLimitCustomPolicy {
    Static(Option<RateLimitRule>),
    Dynamic(Arc<dyn RateLimitRuleResolver>),
}

impl RateLimitCustomRule {
    pub fn limit(path: impl Into<String>, window: u64, max: u32) -> Self {
        Self {
            path: path.into(),
            policy: RateLimitCustomPolicy::Static(Some(RateLimitRule::new(window, max))),
        }
    }

    pub fn disabled(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            policy: RateLimitCustomPolicy::Static(None),
        }
    }

    pub fn dynamic(path: impl Into<String>, resolver: Arc<dyn RateLimitRuleResolver>) -> Self {
        Self {
            path: path.into(),
            policy: RateLimitCustomPolicy::Dynamic(resolver),
        }
    }
}

/// Request metadata supplied to a dynamic Better Auth custom rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitRequest {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: BTreeMap<String, String>,
}

/// Native equivalent of a Better Auth functional `customRules` entry.
#[async_trait]
pub trait RateLimitRuleResolver: Send + Sync {
    /// `None` is Better Auth's `false` return and disables limiting.
    async fn resolve(
        &self,
        request: &RateLimitRequest,
        current_rule: RateLimitRule,
    ) -> Result<Option<RateLimitRule>, AuthError>;
}

/// Result of one atomic Better Auth rate-limit consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitOutcome {
    pub allowed: bool,
    pub retry_after: Option<u64>,
}

impl RateLimitOutcome {
    pub const fn allowed() -> Self {
        Self {
            allowed: true,
            retry_after: None,
        }
    }

    pub const fn denied(retry_after: u64) -> Self {
        Self {
            allowed: false,
            retry_after: Some(retry_after),
        }
    }
}

/// Atomic storage hook matching Better Auth's `rateLimit.customStorage`.
#[async_trait]
pub trait RateLimitStorage: Send + Sync {
    async fn consume(&self, key: &str, rule: RateLimitRule) -> Result<RateLimitOutcome, AuthError>;
}

/// Better Auth rate-limit storage selection.
#[derive(Clone, Default)]
pub enum RateLimitStorageMode {
    #[default]
    Auto,
    Memory,
    Database,
    SecondaryStorage(Arc<dyn RateLimitStorage>),
    Custom(Arc<dyn RateLimitStorage>),
}

/// Better Auth-compatible request rate limiting.
#[derive(Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub window: u64,
    pub max: u32,
    pub storage: RateLimitStorageMode,
    pub custom_rules: Vec<RateLimitCustomRule>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            // Better Auth enables this in production and disables it in
            // development/test. Cargo's release/debug distinction is the
            // native equivalent without introducing environment variables.
            enabled: !cfg!(debug_assertions),
            window: 10,
            max: 100,
            storage: RateLimitStorageMode::Auto,
            custom_rules: Vec::new(),
        }
    }
}

impl RateLimitConfig {
    pub(crate) fn validate(&self) -> Result<(), AuthError> {
        if self.window == 0 || self.max == 0 {
            return invalid("rate-limit window and max must be positive");
        }
        for custom in &self.custom_rules {
            if !valid_path_pattern(&custom.path) {
                return invalid(format!(
                    "rate-limit custom rule path '{}' is invalid",
                    custom.path
                ));
            }
            if matches!(
                &custom.policy,
                RateLimitCustomPolicy::Static(Some(rule)) if rule.window == 0 || rule.max == 0
            ) {
                return invalid(format!(
                    "rate-limit custom rule '{}' must have a positive window and max",
                    custom.path
                ));
            }
        }
        Ok(())
    }

    pub(crate) async fn resolve_rule(
        &self,
        request: &RateLimitRequest,
        plugin_rule: Option<PluginRateLimit>,
    ) -> Result<Option<RateLimitRule>, AuthError> {
        let path = &request.path;
        let mut rule = RateLimitRule::new(self.window, self.max);
        if default_special_rule(path).is_some() {
            rule = default_special_rule(path).expect("checked above");
        }
        if let Some(plugin) = plugin_rule {
            rule = RateLimitRule::new(plugin.window, plugin.max);
        }
        if let Some(custom) = self
            .custom_rules
            .iter()
            .find(|custom| wildcard_match(&custom.path, path))
        {
            return match &custom.policy {
                RateLimitCustomPolicy::Static(rule) => Ok(*rule),
                RateLimitCustomPolicy::Dynamic(resolver) => {
                    let resolved = resolver.resolve(request, rule).await?;
                    if resolved.is_some_and(|rule| rule.window == 0 || rule.max == 0) {
                        return Err(AuthError::InvalidConfiguration(format!(
                            "rate-limit custom rule '{}' returned a zero window or max",
                            custom.path
                        )));
                    }
                    Ok(resolved)
                }
            };
        }
        Ok(Some(rule))
    }

    pub(crate) fn longest_window(&self, plugin_rules: &[PluginRateLimit]) -> u64 {
        let custom = self
            .custom_rules
            .iter()
            .filter_map(|custom| match &custom.policy {
                RateLimitCustomPolicy::Static(Some(rule)) => Some(rule.window),
                _ => None,
            });
        [self.window, 10, 60]
            .into_iter()
            .chain(plugin_rules.iter().map(|rule| rule.window))
            .chain(custom)
            .max()
            .unwrap_or(self.window)
    }
}

fn default_special_rule(path: &str) -> Option<RateLimitRule> {
    if path.starts_with("/sign-in")
        || path.starts_with("/sign-up")
        || path.starts_with("/change-password")
        || path.starts_with("/change-email")
    {
        return Some(RateLimitRule::new(10, 3));
    }
    if path == "/request-password-reset"
        || path == "/send-verification-email"
        || path.starts_with("/forget-password")
        || path == "/email-otp/send-verification-otp"
        || path == "/email-otp/request-password-reset"
    {
        return Some(RateLimitRule::new(60, 3));
    }
    None
}

fn valid_path_pattern(path: &str) -> bool {
    path.starts_with('/') && !path.contains(['?', '#'])
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    fn matches(
        pattern: &[u8],
        value: &[u8],
        pattern_index: usize,
        value_index: usize,
        memo: &mut [Option<bool>],
    ) -> bool {
        let width = value.len() + 1;
        let memo_index = pattern_index * width + value_index;
        if let Some(result) = memo[memo_index] {
            return result;
        }
        let result = match pattern.get(pattern_index) {
            None => value_index == value.len(),
            Some(b'\\') => match pattern.get(pattern_index + 1) {
                Some(literal) => {
                    value.get(value_index) == Some(literal)
                        && matches(pattern, value, pattern_index + 2, value_index + 1, memo)
                }
                None => value.get(value_index) == Some(&b'\\') && value_index + 1 == value.len(),
            },
            Some(b'?') => {
                value.get(value_index).is_some_and(|value| *value != b'/')
                    && matches(pattern, value, pattern_index + 1, value_index + 1, memo)
            }
            Some(b'*') if pattern.get(pattern_index + 1) == Some(&b'*') => {
                matches(pattern, value, pattern_index + 2, value_index, memo)
                    || (value_index < value.len()
                        && matches(pattern, value, pattern_index, value_index + 1, memo))
            }
            Some(b'*') => {
                matches(pattern, value, pattern_index + 1, value_index, memo)
                    || (value.get(value_index).is_some_and(|value| *value != b'/')
                        && matches(pattern, value, pattern_index, value_index + 1, memo))
            }
            Some(literal) => {
                value.get(value_index) == Some(literal)
                    && matches(pattern, value, pattern_index + 1, value_index + 1, memo)
            }
        };
        memo[memo_index] = Some(result);
        result
    }

    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut memo = vec![None; (pattern.len() + 1) * (value.len() + 1)];
    matches(pattern, value, 0, 0, &mut memo)
}

fn invalid(message: impl Into<String>) -> Result<(), AuthError> {
    Err(AuthError::InvalidConfiguration(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn special_plugin_and_custom_rules_follow_better_auth_precedence() {
        let config = RateLimitConfig {
            custom_rules: vec![
                RateLimitCustomRule::limit("/sign-in/*", 5, 2),
                RateLimitCustomRule::disabled("/health"),
            ],
            ..RateLimitConfig::default()
        };
        assert_eq!(
            config
                .resolve_rule(&request("/sign-in/email"), None)
                .await
                .unwrap(),
            Some(RateLimitRule::new(5, 2))
        );
        assert_eq!(
            config
                .resolve_rule(&request("/health"), None)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            config
                .resolve_rule(
                    &request("/plugin"),
                    Some(PluginRateLimit {
                        path: "/plugin",
                        window: 30,
                        max: 4,
                    }),
                )
                .await
                .unwrap(),
            Some(RateLimitRule::new(30, 4))
        );
    }

    fn request(path: &str) -> RateLimitRequest {
        RateLimitRequest {
            method: "GET".into(),
            path: path.into(),
            query: None,
            headers: BTreeMap::new(),
        }
    }

    #[test]
    fn wildcard_matching_is_anchored() {
        assert!(wildcard_match("/sign-in/*", "/sign-in/email"));
        assert!(wildcard_match("/*/callback/*", "/sso/callback/acme"));
        assert!(wildcard_match(
            "/**/callback/*",
            "/nested/sso/callback/acme"
        ));
        assert!(!wildcard_match("/sign-in/*", "/prefix/sign-in/email"));
        assert!(!wildcard_match("/sign-in/*", "/sign-in/email/verification"));
        assert!(!wildcard_match("/sign-in/*/done", "/sign-in/email"));
    }
}
