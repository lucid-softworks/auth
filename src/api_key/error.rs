#[derive(Debug, Clone, thiserror::Error)]
pub enum ApiKeyError {
    #[error("Unauthorized or invalid session")]
    UnauthorizedSession,
    #[error("API Key not found")]
    NotFound,
    #[error("API Key is disabled")]
    Disabled,
    #[error("API Key has expired")]
    Expired,
    #[error("API Key has reached its usage limit")]
    UsageExceeded,
    #[error("Rate limit exceeded")]
    RateLimited { retry_after_milliseconds: i64 },
    #[error("Invalid API key")]
    Invalid,
    #[error("The property you're trying to set can only be set from the server auth instance only")]
    ServerOnlyProperty,
    #[error("No values to update")]
    NoValuesToUpdate,
    #[error("Metadata is disabled")]
    MetadataDisabled,
    #[error("metadata must be an object or undefined")]
    InvalidMetadata,
    #[error("The prefix length is either too large or too small")]
    InvalidPrefixLength,
    #[error("The name length is either too large or too small")]
    InvalidNameLength,
    #[error("API Key name is required")]
    NameRequired,
    #[error("The expiresIn is smaller than the predefined minimum value")]
    ExpiresTooSmall,
    #[error("The expiresIn is larger than the predefined maximum value")]
    ExpiresTooLarge,
    #[error("Custom key expiration values are disabled")]
    ExpirationDisabled,
    #[error("refillAmount is required when refillInterval is provided")]
    RefillAmountRequired,
    #[error("refillInterval is required when refillAmount is provided")]
    RefillIntervalRequired,
    #[error("API key permissions are insufficient")]
    PermissionDenied,
    #[error("Organization plugin is required for organization-owned API keys")]
    OrganizationPluginRequired,
}
