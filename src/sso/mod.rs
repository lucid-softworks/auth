//! Native enterprise SSO surface compatible with `@better-auth/sso` 1.7.1.

mod config;
mod plugin;
mod schema;

pub use config::SsoOptions;
pub use plugin::SsoPlugin;

/// Published `@better-auth/sso` compatibility target.
pub const VERSION: &str = "1.7.1";
