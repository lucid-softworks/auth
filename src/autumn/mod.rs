mod callbacks;
mod config;
mod error;
mod identity;
mod metadata;
mod plugin;

#[cfg(feature = "axum")]
mod axum;
pub(crate) mod schema;
pub mod transport;

pub use callbacks::{AutumnIdentityProvider, FnAutumnIdentityProvider, SyncAutumnIdentityProvider};
pub use config::{AutumnCustomerScope, AutumnOptions};
pub use error::AutumnIdentityError;
pub use identity::AutumnIdentity;
pub use plugin::AutumnPlugin;
pub use transport::{AutumnClient, AutumnHttpClient, AutumnOperation, AutumnProviderError};

pub const AUTUMN_ADAPTER_VERSION: &str = "1.2.53";
pub const AUTUMN_SDK_VERSION: &str = "0.10.18";
