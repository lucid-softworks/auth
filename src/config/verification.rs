use crate::AuthError;
use std::{fmt::Debug, sync::Arc};

#[async_trait::async_trait]
pub trait VerificationIdentifierHasher: Debug + Send + Sync {
    async fn hash(&self, identifier: &str) -> Result<String, AuthError>;
}

#[derive(Debug, Clone, Default)]
pub enum VerificationIdentifierStorage {
    #[default]
    Plain,
    Hashed,
    Custom(Arc<dyn VerificationIdentifierHasher>),
}

#[derive(Debug, Clone, Default)]
pub struct VerificationIdentifierConfig {
    pub default: VerificationIdentifierStorage,
    /// Prefix rules are evaluated in this order, matching JavaScript object
    /// insertion order.
    pub overrides: Vec<(String, VerificationIdentifierStorage)>,
}

#[derive(Debug, Clone, Default)]
pub struct VerificationConfig {
    pub additional_fields: crate::AdditionalFieldSet,
    pub disable_cleanup: bool,
    pub store_identifier: VerificationIdentifierConfig,
    /// Mirrors verification values to the database when secondary storage is
    /// configured. Better Auth defaults this to false.
    pub store_in_database: bool,
}
