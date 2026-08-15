/// Errors returned by authentication operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid username or password")]
    InvalidCredentials,
    #[error("too many sign-in attempts")]
    RateLimited,
    #[error("anonymous guest access is disabled")]
    AnonymousAccessDisabled,
    #[error("the session is invalid or expired")]
    InvalidSession,
    #[error("the account is disabled")]
    AccountDisabled,
    #[error("the requested authentication resource was not found")]
    NotFound,
    #[error("the current account is not permitted to perform this action")]
    Forbidden,
    #[error("the final owner account cannot be removed or disabled")]
    LastOwner,
    #[error("the guest grant is invalid, expired, exhausted, or revoked")]
    InvalidGuestGrant,
    #[error("passkey support is not configured")]
    PasskeyDisabled,
    #[error("a passkey ceremony is missing or expired")]
    PasskeyChallengeExpired,
    #[error("passkey verification failed")]
    PasskeyVerificationFailed,
    #[error("the passkey is already registered")]
    CredentialAlreadyRegistered,
    #[error("authentication configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error("authentication storage failed: {0}")]
    Storage(String),
    #[error("authentication worker failed")]
    Worker,
}
