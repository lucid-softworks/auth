//! Native authentication with a Better Auth-compatible HTTP surface.

mod breached_password;
mod error;
mod memory;
mod model;
mod origin;
mod service;
mod store;

#[cfg(feature = "axum")]
pub mod axum;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod protocol;

pub use breached_password::{PasswordBreachChecker, PwnedPasswordsChecker};
pub use error::AuthError;
pub use memory::MemoryStore;
pub use model::{
    ApiKey, Assurance, AuditEvent, AuthSession, AuthUser, GuestGrant, IssuedApiKey,
    IssuedGuestGrant, NewApiKey, NewGuestGrant, NewPasswordUser, Principal, SessionWithUser,
    StoredPasskey, VerifiedApiKey,
};
pub use origin::TrustedOrigin;
pub use service::{
    AuthConfig, AuthService, HashedPasswordUser, PasskeyConfig, PasskeyRegistrationResult,
    PasswordChangeResult, RecoveryCodeStatus, SignInResult,
};
pub use store::{AccessStore, ApiKeyStore, AuthStore, PasskeyDeleteOutcome, SecurityStore};
