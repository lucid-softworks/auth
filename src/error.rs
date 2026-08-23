/// Errors returned by authentication operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error(transparent)]
    ApiKey(#[from] crate::ApiKeyError),
    #[error("invalid username or password")]
    InvalidCredentials,
    #[error("invalid email or password")]
    InvalidEmailOrPassword,
    #[error("invalid email")]
    InvalidEmail,
    #[error("email and password authentication is disabled")]
    EmailPasswordDisabled,
    #[error("email and password sign up is disabled")]
    EmailPasswordSignUpDisabled,
    #[error("email is not verified")]
    EmailNotVerified,
    #[error("verification email is not enabled")]
    VerificationEmailNotEnabled,
    #[error("email does not match the active session")]
    EmailMismatch,
    #[error("email is already verified")]
    EmailAlreadyVerified,
    #[error("verification token is invalid")]
    InvalidToken,
    #[error("verification token has expired")]
    TokenExpired,
    #[error("verification token user was not found")]
    VerificationUserNotFound,
    #[error("password reset is disabled")]
    ResetPasswordDisabled,
    #[error("password reset token is invalid")]
    InvalidPasswordResetToken,
    #[error("password reset token user was not found")]
    PasswordResetUserNotFound,
    #[error("too many sign-in attempts")]
    RateLimited,
    #[error("anonymous guest access is disabled")]
    AnonymousAccessDisabled,
    #[error("the session is invalid or expired")]
    InvalidSession,
    #[error("authentication is required")]
    Unauthorized,
    #[error("the session is not fresh")]
    SessionNotFresh,
    #[error("the account is disabled")]
    AccountDisabled,
    #[error("the requested authentication resource was not found")]
    NotFound,
    #[error("a user with that username or email already exists")]
    UserAlreadyExists,
    #[error("a user with that email already exists")]
    UserAlreadyExistsEmail,
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
    #[error("the passkey used for authentication was not found")]
    PasskeyAuthenticationNotFound,
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
    #[error("a passkey ceremony is missing or expired")]
    PasskeyChallengeExpired,
    #[error("passkey verification failed")]
    PasskeyVerificationFailed,
    #[error("the WebAuthn request origin is missing")]
    PasskeyOriginMissing,
    #[error("passkey registration verification failed")]
    PasskeyRegistrationFailed,
    #[error("passkey registration requires an authenticated session")]
    PasskeySessionRequired,
    #[error("the session cannot register this passkey")]
    PasskeyRegistrationForbidden,
    #[error("passkey registration requires a user resolver")]
    PasskeyResolverRequired,
    #[error("the resolved passkey user is invalid")]
    PasskeyResolvedUserInvalid,
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
