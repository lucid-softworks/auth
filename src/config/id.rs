use uuid::Uuid;

/// Configured native ID generation used by Better Auth model factories.
pub trait AuthIdGenerator: std::fmt::Debug + Send + Sync {
    /// Returns `None` to use the native UUID fallback.
    fn generate(&self, model: &str) -> Option<Uuid>;
}
