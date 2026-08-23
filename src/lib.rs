//! Native authentication with a Better Auth-compatible HTTP surface.

mod api_key;
mod breached_password;
mod client_ip;
mod config;
mod cookie;
mod email;
mod error;
mod magic_link;
mod memory;
mod model;
mod origin;
mod passkey;
mod plugin;
mod service;
mod store;

#[cfg(feature = "axum")]
pub mod axum;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod protocol;

pub use api_key::{
    ApiKeyConfiguration, ApiKeyError, ApiKeyExpirationConfig, ApiKeyGenerator, ApiKeyPlugin,
    ApiKeyRateLimitConfig, ApiKeyReference, ApiKeyStartingCharactersConfig,
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
pub use magic_link::{
    MagicLinkConfig, MagicLinkEmail, MagicLinkPlugin, MagicLinkRequestContext, MagicLinkSender,
    MagicLinkTokenGenerator, MagicLinkTokenHasher, MagicLinkTokenStorage,
};
pub use memory::MemoryStore;
pub use model::{
    ApiKey, Assurance, AuditEvent, AuthSession, AuthUser, GuestGrant, IssuedApiKey,
    IssuedGuestGrant, NewApiKey, NewGuestGrant, NewPasswordUser, Principal, SessionWithUser,
    StoredPasskey, VerificationValue, VerifiedApiKey,
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
    ApiKeySortDirection, ApiKeyUpdate, AuthService, EmailSignUpInput, EmailSignUpResult,
    EmailVerificationResult, HashedPasswordUser, PasskeyRegistrationRequest,
    PasskeyRegistrationResult, PasskeyRegistrationVerification, PasswordChangeResult,
    RecoveryCodeStatus, SignInResult,
};
pub use store::{
    AccessStore, ApiKeyStore, ApiKeyUseOutcome, AuthStore, EmailVerificationOutcome,
    PasskeyDeleteOutcome, PasswordResetOutcome, SecurityStore, VerificationStore,
};
