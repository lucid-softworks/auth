#[cfg(feature = "axum")]
mod axum;
mod callbacks;
mod config;
mod customer_lifecycle;
mod metadata;
mod model;
mod plugin;
mod provider;
mod transport;
mod webhook;

pub use callbacks::*;
pub use config::*;
pub use model::*;
pub use plugin::*;
pub use provider::*;
pub use transport::*;
pub use webhook::*;

pub const COMMET_ADAPTER_VERSION: &str = "8.1.0";
pub const COMMET_SDK_VERSION: &str = "9.1.0";
