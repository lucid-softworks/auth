//! Native authentication with a Better Auth-compatible HTTP surface.

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

pub use error::AuthError;
pub use memory::MemoryStore;
pub use model::{Assurance, AuthSession, AuthUser, NewPasswordUser, Principal, SessionWithUser};
pub use service::{AuthConfig, AuthService, SignInResult};
pub use store::AuthStore;
