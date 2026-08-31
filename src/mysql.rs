//! Native MySQL persistence for Better Auth-compatible schemas.
//!
//! SQLx negotiates MySQL's `FOUND_ROWS` capability and initializes its own
//! connections with a `+00:00` session timezone. Caller-supplied pools must
//! preserve that timezone and pass [`MySqlStore::ready`] before serving.

mod access;
mod adapter;
mod agent_auth;
mod api_key;
mod codec;
mod dash;
mod device_authorization;
mod error;
mod jwt;
mod migration;
mod oauth;
mod oauth_provider;
mod organization;
mod passkey;
mod phone_number;
mod query;
mod schema;
mod security;
mod session;
mod siwe;
mod transaction;
mod two_factor;
mod user;
mod value;
mod verification;

pub use adapter::{MySqlAdapterConfig, MySqlStore};
pub use migration::{
    MySqlMigrationError, MySqlMigrationMode, MySqlMigrationPlan, MySqlMigrationStep,
};
pub use query::{
    MySqlComparisonMode, MySqlFilter, MySqlFilterConnector, MySqlFilterOperator,
    MySqlFindOptions, MySqlSort, MySqlSortDirection, MySqlTransaction,
};
