//! Native MySQL persistence for Better Auth-compatible schemas.
//!
//! SQLx negotiates MySQL's `FOUND_ROWS` capability and initializes its own
//! connections with a `+00:00` session timezone. Caller-supplied pools must
//! preserve that timezone and pass [`MySqlStore::ready`] before serving.

mod adapter;
mod migration;
mod query;
mod schema;
mod value;

pub use adapter::{MySqlAdapterConfig, MySqlStore};
pub use migration::{
    MySqlMigrationError, MySqlMigrationMode, MySqlMigrationPlan, MySqlMigrationStep,
};
pub use query::{
    MySqlComparisonMode, MySqlFilter, MySqlFilterConnector, MySqlFilterOperator,
    MySqlFindOptions, MySqlSort, MySqlSortDirection, MySqlTransaction,
};
