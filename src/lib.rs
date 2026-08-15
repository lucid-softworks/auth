//! Native authentication with a Better Auth-compatible HTTP surface.

mod breached_password;
mod error;
mod memory;
mod model;
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
    Assurance, AuditEvent, AuthSession, AuthUser, GuestGrant, IssuedGuestGrant, NewGuestGrant,
    NewPasswordUser, Principal, SessionWithUser, StoredPasskey,
};
pub use service::{
    AuthConfig, AuthService, HashedPasswordUser, PasskeyConfig, PasskeyRegistrationResult,
    PasswordChangeResult, RecoveryCodeStatus, SignInResult,
};
pub use store::{AccessStore, AuthStore, SecurityStore};
