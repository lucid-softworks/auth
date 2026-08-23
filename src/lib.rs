//! Native authentication with a Better Auth-compatible HTTP surface.

mod api_key;
mod audit;
mod breached_password;
mod client_ip;
mod config;
mod cookie;
mod email;
mod error;
mod guest_capability;
mod magic_link;
mod memory;
mod model;
mod origin;
mod passkey;
mod plugin;
mod service;
mod store;
mod two_factor;
mod user_deletion;
mod username;

#[cfg(feature = "axum")]
pub mod axum;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod protocol;

pub use api_key::{
    ApiKeyConfiguration, ApiKeyError, ApiKeyExpirationConfig, ApiKeyGenerator, ApiKeyPlugin,
    ApiKeyRateLimitConfig, ApiKeyReference, ApiKeyStartingCharactersConfig,
};
pub use audit::{
    AUDIT_ACTION_VOCABULARY_VERSION, AuditEvent, AuditMetadata, AuditOutcome, AuditPlugin,
    AuditStore, MemoryAuditStore,
};
pub use breached_password::{PasswordBreachChecker, PwnedPasswordsChecker};
pub use client_ip::IpAddressConfig;
pub use config::{AuthConfig, EmailPasswordConfig};
pub use cookie::{CookieAttributes, CookieConfig, CookieOptions, SameSite};
pub use email::{
    EmailVerificationConfig, PasswordResetCallback, PasswordResetEmail, PasswordResetEmailSender,
    VerificationEmail, VerificationEmailSender,
};
pub use error::AuthError;
pub use guest_capability::{
    GuestCapabilityPlugin, GuestCapabilityPrincipal, GuestCapabilityStore, GuestGrant,
    GuestGrantSignInResult, IssuedGuestGrant, NewGuestGrant,
};
pub use magic_link::{
    MagicLinkConfig, MagicLinkEmail, MagicLinkPlugin, MagicLinkRequestContext, MagicLinkSender,
    MagicLinkTokenGenerator, MagicLinkTokenHasher, MagicLinkTokenStorage,
};
pub use memory::MemoryStore;
pub use model::{
    ApiKey, Assurance, AuthSession, AuthUser, IssuedApiKey, NewApiKey, NewPasswordUser, Principal,
    SessionWithUser, StoredPasskey, VerificationValue, VerifiedApiKey,
};
pub use origin::TrustedOrigin;
pub use passkey::{
    PasskeyAuthenticationCallback, PasskeyAuthenticationConfig, PasskeyAuthenticationVerified,
    PasskeyAuthenticatorSelection, PasskeyConfig, PasskeyExtensions, PasskeyExtensionsResolver,
    PasskeyPlugin, PasskeyRegistrationCallback, PasskeyRegistrationConfig,
    PasskeyRegistrationOverride, PasskeyRegistrationUser, PasskeyRegistrationUserResolver,
    PasskeyRegistrationVerified,
};
pub use plugin::{
    AfterAuthEvent, AuthPlugin, BeforeAuthEvent, PluginClientMetadata, PluginCookie,
    PluginDescriptor, PluginEndpoint, PluginHttpMethod, PluginMiddleware, PluginMigration,
    PluginMigrationContribution, PluginRateLimit,
};
#[cfg(feature = "axum")]
pub use plugin::{AxumPluginRoute, PluginSession};
pub use service::{
    ApiKeySortDirection, ApiKeyUpdate, AuthService, DeleteUserResult, EmailSignUpInput,
    EmailSignUpResult, EmailVerificationResult, HashedPasswordUser, PasskeyRegistrationRequest,
    PasskeyRegistrationResult, PasskeyRegistrationVerification, PasswordChangeResult,
    RecoveryCodeStatus, SignInResult,
};
pub use store::{
    AccessStore, ApiKeyStore, ApiKeyUseOutcome, AuthStore, EmailVerificationOutcome,
    PasskeyDeleteOutcome, PasswordResetOutcome, SecurityStore, UserProfileUpdate,
    VerificationStore,
};
pub use two_factor::{
    AccountLockoutConfig, BackupCodeConfig, MemoryTwoFactorStore, OtpConfig, TotpConfig,
    TwoFactorConfig, TwoFactorError, TwoFactorOtp, TwoFactorOtpSender, TwoFactorPlugin,
    TwoFactorRecord, TwoFactorStore,
};
pub use user_deletion::{
    DeleteAccountVerification, DeleteAccountVerificationSender, DeleteUserConfig, UserConfig,
    UserDeletionCallback,
};
pub use username::{
    UsernameConfig, UsernameError, UsernameNormalizer, UsernamePlugin, UsernameValidationOrder,
    UsernameValidationTiming, UsernameValidator,
};
