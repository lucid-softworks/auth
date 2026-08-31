//! Native Microsoft SQL Server persistence for Better Auth-compatible schemas.
//!
//! The backend uses Tiberius and a caller-configurable in-process BB8 pool. It
//! preserves Better Auth's MSSQL transaction default: multi-operation adapter
//! transactions are disabled unless explicitly enabled.

mod adapter;
mod migration;
mod query;
mod schema;
mod statement;
mod value;

pub use adapter::{MssqlAdapterConfig, MssqlPool, MssqlStore};
pub use migration::{
    MssqlMigrationError, MssqlMigrationMode, MssqlMigrationPlan, MssqlMigrationStep,
};
pub use query::{
    MssqlComparisonMode, MssqlFilter, MssqlFilterConnector, MssqlFilterOperator,
    MssqlFindOptions, MssqlSort, MssqlSortDirection,
};
