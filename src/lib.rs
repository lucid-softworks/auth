//! Native authentication with a Better Auth-compatible HTTP surface.

mod breached_password;
mod client_ip;
mod config;
mod cookie;
mod error;
mod memory;
mod model;
mod origin;
mod plugin;
mod service;
mod store;

#[cfg(feature = "axum")]
pub mod axum;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod protocol;

pub use breached_password::{PasswordBreachChecker, PwnedPasswordsChecker};
pub use client_ip::IpAddressConfig;
pub use config::{AuthConfig, PasskeyConfig};
pub use cookie::{CookieAttributes, CookieConfig, CookieOptions, SameSite};
pub use error::AuthError;
pub use memory::MemoryStore;
pub use model::{
    ApiKey, Assurance, AuditEvent, AuthSession, AuthUser, GuestGrant, IssuedApiKey,
    IssuedGuestGrant, NewApiKey, NewGuestGrant, NewPasswordUser, Principal, SessionWithUser,
    StoredPasskey, VerificationValue, VerifiedApiKey,
};
pub use origin::TrustedOrigin;
#[cfg(feature = "axum")]
pub use plugin::AxumPluginRoute;
pub use plugin::{
    AfterAuthEvent, AuthPlugin, BeforeAuthEvent, PluginClientMetadata, PluginCookie,
    PluginDescriptor, PluginEndpoint, PluginHttpMethod, PluginMiddleware, PluginMigration,
    PluginMigrationContribution, PluginRateLimit,
};
pub use service::{
    AuthService, HashedPasswordUser, PasskeyRegistrationResult, PasswordChangeResult,
    RecoveryCodeStatus, SignInResult,
};
pub use store::{
    AccessStore, ApiKeyStore, AuthStore, PasskeyDeleteOutcome, SecurityStore, VerificationStore,
};
