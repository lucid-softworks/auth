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
    #[error("a user with that username or email already exists")]
    UserAlreadyExists,
    #[error("the credential account was not found")]
    CredentialAccountNotFound,
    #[error("the current password is incorrect")]
    InvalidPassword,
    #[error("the new password is too short")]
    PasswordTooShort,
    #[error("the new password is too long")]
    PasswordTooLong,
    #[error("the password has appeared in a known data breach")]
    PasswordCompromised,
    #[error("the breached-password check is temporarily unavailable")]
    PasswordCheckUnavailable,
    #[error("the passkey was not found")]
    PasskeyNotFound,
    #[error("an MFA-required account must keep at least one passkey")]
    LastPasskey,
    #[error("the current account is not permitted to perform this action")]
    Forbidden,
    #[error("recent multi-factor authentication is required for this action")]
    StepUpRequired,
    #[error("the final owner account cannot be removed or disabled")]
    LastOwner,
    #[error("local recovery requires the named account to be the sole owner")]
    SoleOwnerRecoveryUnavailable,
    #[error("the guest grant is invalid, expired, exhausted, or revoked")]
    InvalidGuestGrant,
    #[error("the API key is invalid, expired, or revoked")]
    InvalidApiKey,
    #[error("the request origin is not trusted")]
    InvalidOrigin,
    #[error("the request origin is missing or null")]
    MissingOrigin,
    #[error("the callback URL is not trusted")]
    InvalidCallbackUrl,
    #[error("the redirect URL is not trusted")]
    InvalidRedirectUrl,
    #[error("the error callback URL is not trusted")]
    InvalidErrorCallbackUrl,
    #[error("the new-user callback URL is not trusted")]
    InvalidNewUserCallbackUrl,
    #[error("cross-site navigation login is blocked")]
    CrossSiteNavigationLogin,
    #[error("the authentication request is invalid: {0}")]
    InvalidRequest(String),
    #[error("passkey support is not configured")]
    PasskeyDisabled,
    #[error("a passkey ceremony is missing or expired")]
    PasskeyChallengeExpired,
    #[error("passkey verification failed")]
    PasskeyVerificationFailed,
    #[error("the passkey is already registered")]
    CredentialAlreadyRegistered,
    #[error("recovery codes are not enabled for this account")]
    RecoveryCodesNotEnabled,
    #[error("the recovery code is invalid")]
    InvalidRecoveryCode,
    #[error("authentication configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error("authentication storage failed: {0}")]
    Storage(String),
    #[error("authentication worker failed")]
    Worker,
}
