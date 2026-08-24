use crate::{AdditionalFieldSet, AuthError};
use chrono::Duration;

/// Better Auth's three session cookie-cache wire formats.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CookieCacheStrategy {
    #[default]
    Compact,
    Jwt,
    Jwe,
}

/// Stateless cookie-cache refresh policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CookieCacheRefresh {
    #[default]
    Disabled,
    /// Refresh once 20% of the configured cache lifetime remains.
    Enabled,
    /// Refresh once this much lifetime remains.
    UpdateAge(Duration),
}

/// Better Auth `session.cookieCache` settings.
#[derive(Debug, Clone)]
pub struct CookieCacheConfig {
    pub enabled: bool,
    pub max_age: Duration,
    pub strategy: CookieCacheStrategy,
    pub refresh_cache: CookieCacheRefresh,
    pub version: String,
}

impl Default for CookieCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_age: Duration::minutes(5),
            strategy: CookieCacheStrategy::Compact,
            refresh_cache: CookieCacheRefresh::Disabled,
            version: "1".into(),
        }
    }
}

/// Where live session state is authoritative.
///
/// Better Auth infers this from whether a database or secondary storage is
/// installed. Lucid Auth always receives an `AuthStore`, so the native API
/// makes the DB-less session case explicit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SessionStorageMode {
    #[default]
    Database,
    Stateless,
}

/// Better Auth-compatible session behavior.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub additional_fields: AdditionalFieldSet,
    pub disable_session_refresh: bool,
    pub store_session_in_database: bool,
    pub preserve_session_in_database: bool,
    pub cookie_cache: CookieCacheConfig,
    pub storage_mode: SessionStorageMode,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            additional_fields: AdditionalFieldSet::new(),
            disable_session_refresh: false,
            store_session_in_database: false,
            preserve_session_in_database: false,
            cookie_cache: CookieCacheConfig::default(),
            storage_mode: SessionStorageMode::Database,
        }
    }
}

impl SessionConfig {
    pub(crate) fn validate(&self) -> Result<(), AuthError> {
        if self.cookie_cache.max_age <= Duration::zero() {
            return invalid("session cookie-cache max age must be positive");
        }
        if let CookieCacheRefresh::UpdateAge(update_age) = self.cookie_cache.refresh_cache
            && (update_age <= Duration::zero() || update_age >= self.cookie_cache.max_age)
        {
            return invalid(
                "session cookie-cache update age must be positive and less than max age",
            );
        }
        if self.cookie_cache.version.is_empty() {
            return invalid("session cookie-cache version must not be empty");
        }
        if self.storage_mode == SessionStorageMode::Stateless && !self.cookie_cache.enabled {
            return invalid("stateless sessions require session cookie cache");
        }
        Ok(())
    }
}

fn invalid<T>(message: &str) -> Result<T, AuthError> {
    Err(AuthError::InvalidConfiguration(message.into()))
}
