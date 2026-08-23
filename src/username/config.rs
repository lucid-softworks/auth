use async_trait::async_trait;
use std::{fmt, sync::Arc};

/// Synchronous username normalization callback.
pub trait UsernameNormalizer: Send + Sync {
    fn normalize(&self, value: &str) -> String;
}

impl<F> UsernameNormalizer for F
where
    F: Fn(&str) -> String + Send + Sync,
{
    fn normalize(&self, value: &str) -> String {
        self(value)
    }
}

/// Potentially asynchronous username validation callback.
#[async_trait]
pub trait UsernameValidator: Send + Sync {
    async fn is_valid(&self, value: &str) -> bool;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UsernameValidationTiming {
    #[default]
    PreNormalization,
    PostNormalization,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsernameValidationOrder {
    pub username: UsernameValidationTiming,
    pub display_username: UsernameValidationTiming,
}

/// Runtime options matching Better Auth's `username()` plugin.
#[derive(Clone)]
pub struct UsernameConfig {
    pub min_username_length: usize,
    pub max_username_length: usize,
    pub username_validator: Option<Arc<dyn UsernameValidator>>,
    pub display_username_validator: Option<Arc<dyn UsernameValidator>>,
    /// `false` disables Better Auth's default lower-case normalization.
    pub normalize_username: bool,
    pub username_normalizer: Option<Arc<dyn UsernameNormalizer>>,
    pub display_username_normalizer: Option<Arc<dyn UsernameNormalizer>>,
    pub validation_order: UsernameValidationOrder,
    pub immutable_username: bool,
    pub display_username: bool,
}

impl Default for UsernameConfig {
    fn default() -> Self {
        Self {
            min_username_length: 3,
            max_username_length: 30,
            username_validator: None,
            display_username_validator: None,
            normalize_username: true,
            username_normalizer: None,
            display_username_normalizer: None,
            validation_order: UsernameValidationOrder::default(),
            immutable_username: false,
            display_username: true,
        }
    }
}

impl fmt::Debug for UsernameConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UsernameConfig")
            .field("min_username_length", &self.min_username_length)
            .field("max_username_length", &self.max_username_length)
            .field("username_validator", &self.username_validator.is_some())
            .field(
                "display_username_validator",
                &self.display_username_validator.is_some(),
            )
            .field("normalize_username", &self.normalize_username)
            .field("username_normalizer", &self.username_normalizer.is_some())
            .field(
                "display_username_normalizer",
                &self.display_username_normalizer.is_some(),
            )
            .field("validation_order", &self.validation_order)
            .field("immutable_username", &self.immutable_username)
            .field("display_username", &self.display_username)
            .finish()
    }
}
