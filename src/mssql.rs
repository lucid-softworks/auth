//! Native Microsoft SQL Server persistence for Better Auth-compatible schemas.
//!
//! The backend uses Tiberius and a caller-configurable in-process BB8 pool. It
//! preserves Better Auth's MSSQL transaction default: multi-operation adapter
//! transactions are disabled unless explicitly enabled.

mod adapter;
mod access;
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
mod statement;
mod transaction;
mod two_factor;
mod user;
mod value;
mod verification;

pub use adapter::{MssqlAdapterConfig, MssqlPool, MssqlStore};
pub use migration::{
    MssqlMigrationError, MssqlMigrationMode, MssqlMigrationPlan, MssqlMigrationStep,
};
pub use query::{
    MssqlComparisonMode, MssqlFilter, MssqlFilterConnector, MssqlFilterOperator,
    MssqlFindOptions, MssqlSort, MssqlSortDirection, MssqlTransaction,
};
