#[cfg(feature = "axum")]
mod axum;
mod callbacks;
mod config;
mod customer_lifecycle;
mod metadata;
mod model;
mod plugin;
mod provider;
mod schema;
#[cfg(feature = "axum")]
mod service;
mod transport;
pub mod webhook;

pub use callbacks::*;
pub use config::*;
pub use model::*;
pub use plugin::*;
pub use provider::*;
pub use schema::*;
pub use transport::*;

pub const DODO_PAYMENTS_ADAPTER_VERSION: &str = "1.6.5";
pub const DODO_PAYMENTS_CORE_VERSION: &str = "0.3.14";
pub const DODO_PAYMENTS_SDK_VERSION: &str = "2.47.0";
