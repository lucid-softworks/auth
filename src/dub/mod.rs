#[cfg(feature = "axum")]
mod axum;
mod config;
mod cookie;
mod lead;
mod lifecycle;
mod plugin;

pub use config::{DubOAuthOptions, DubOptions};
pub use lead::{
    DubCustomLeadError, DubCustomLeadTrack, DubLead, DubLeadError, DubLeadTracker,
    FnDubCustomLeadTrack, FnDubLeadTracker,
};
pub use plugin::DubPlugin;

pub const DUB_ADAPTER_VERSION: &str = "0.0.6";
pub const DUB_SDK_VERSION: &str = "0.66.5";
