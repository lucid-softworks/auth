/// Errors returned by authentication operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error(transparent)]
    Admin(#[from] crate::AdminError),
    #[error(transparent)]
    ApiKey(#[from] crate::ApiKeyError),
    #[error(transparent)]
    Username(#[from] crate::UsernameError),
    #[error(transparent)]
    TwoFactor(#[from] crate::TwoFactorError),
    #[error(transparent)]
    StepUp(#[from] crate::StepUpError),
    #[error(transparent)]
    OperatorSecurity(#[from] crate::OperatorSecurityError),
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
    #[error("change email is disabled")]
    ChangeEmailDisabled,
    #[error("email is the same")]
    EmailIsSame,
    #[error("the verification token does not belong to the active user")]
    InvalidUser,
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
    #[error("email was not generated in a valid format")]
    AnonymousInvalidEmail,
    #[error("failed to create anonymous user")]
    AnonymousUserCreationFailed,
    #[error("could not create anonymous session")]
    AnonymousSessionCreationFailed,
    #[error("anonymous users cannot sign in again anonymously")]
    AnonymousSignInAgain,
    #[error("failed to delete anonymous user")]
    AnonymousUserDeletionFailed,
    #[error("failed to delete anonymous user sessions")]
    AnonymousUserSessionDeletionFailed,
    #[error("the user is not anonymous")]
    UserIsNotAnonymous,
    #[error("deleting anonymous users is disabled")]
    AnonymousUserDeletionDisabled,
    #[error("the session is invalid or expired")]
    InvalidSession,
    #[error("authentication is required")]
    Unauthorized,
    #[error("the session is not fresh")]
    SessionNotFresh,
    #[error("{0}")]
    AccountDisabled(String),
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
    #[error("the current session has expired for this operation")]
    SessionExpired,
    #[error("the account-deletion token is invalid")]
    InvalidDeleteUserToken,
    #[error("failed to get user info")]
    DeleteUserInfoNotFound,
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
    #[error("the guest grant is invalid, expired, exhausted, or revoked")]
    InvalidGuestGrant,
    #[error("the request origin is not trusted")]
    InvalidOrigin,
    #[error("the request origin is missing or null")]
    MissingOrigin,
    #[error("the callback URL is not trusted")]
    InvalidCallbackUrl,
    #[error("the social provider was not found")]
    OAuthProviderNotFound,
    #[error("the social provider does not support ID-token sign in")]
    OAuthIdTokenNotSupported,
    #[error("the OAuth authorization code is invalid")]
    OAuthInvalidCode,
    #[error("the OAuth token is invalid")]
    OAuthInvalidToken,
    #[error("the OAuth provider did not return usable user information")]
    OAuthUserInfoUnavailable,
    #[error("the OAuth provider did not return an email address")]
    OAuthEmailNotFound,
    #[error("the OAuth state is missing, expired, or does not match")]
    OAuthStateMismatch,
    #[error("the OAuth issuer does not match the configured provider")]
    OAuthIssuerMismatch,
    #[error("the OAuth provider requires a bound ID-token nonce")]
    OAuthNonceBindingMissing,
    #[error("the OAuth account is not linked")]
    OAuthAccountNotLinked,
    #[error("social sign up is disabled")]
    OAuthSignupDisabled,
    #[error("the account was not found")]
    AccountNotFound,
    #[error("the final account cannot be unlinked")]
    FailedToUnlinkLastAccount,
    #[error("the social account is already linked")]
    SocialAccountAlreadyLinked,
    #[error("account linking is not allowed")]
    LinkingNotAllowed,
    #[error("linking an account with a different email is not allowed")]
    LinkingDifferentEmailsNotAllowed,
    #[error("provider {0} is not supported")]
    OAuthProviderNotSupported(String),
    #[error("provider {0} does not support token refreshing")]
    OAuthTokenRefreshNotSupported(String),
    #[error("the account is not associated with a configured social provider")]
    OAuthProviderNotConfigured,
    #[error("the account has no refresh token")]
    OAuthRefreshTokenNotFound,
    #[error("failed to refresh the provider access token")]
    OAuthFailedToRefreshToken,
    #[error("failed to obtain a valid provider access token")]
    OAuthFailedToGetAccessToken,
    #[error("the account has no access token")]
    OAuthAccessTokenNotFound,
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
    #[error("authentication configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error("authentication storage failed: {0}")]
    Storage(String),
    #[error("authentication worker failed")]
    Worker,
}
