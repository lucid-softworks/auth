//! Native local SQLite persistence for Better Auth-compatible schemas.
//!
//! The backend owns no SQLite policy. Callers choose foreign-key enforcement,
//! journal mode, busy timeout, synchronous mode, shared cache, and pool size on
//! their supplied [`sqlx::SqlitePool`] or connection options.

mod access;
mod adapter;
mod agent_auth;
mod api_key;
mod codec;
mod dash;
mod device_authorization;
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

pub use adapter::{SqliteAdapterConfig, SqliteStore};
pub use migration::{
    SqliteMigrationError, SqliteMigrationMode, SqliteMigrationPlan, SqliteMigrationStep,
};
pub use query::{
    SqliteComparisonMode, SqliteFilter, SqliteFilterConnector, SqliteFilterOperator,
    SqliteFindOptions, SqliteSort, SqliteSortDirection, SqliteTransaction,
};
