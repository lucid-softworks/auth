//! Native Cloudflare D1 persistence for Better Auth-compatible schemas.
//!
//! D1 uses SQLite value and schema semantics, but deliberately has no local
//! SQLx driver, interactive transaction, or streaming-query surface.

mod adapter;
mod migration;
mod query;
mod schema;
mod transport;
mod value;

pub use adapter::{D1AdapterConfig, D1Store};
pub use migration::{D1MigrationError, D1MigrationMode, D1MigrationPlan, D1MigrationStep};
pub use query::{
    D1ComparisonMode, D1Filter, D1FilterConnector, D1FilterOperator, D1FindOptions, D1Sort,
    D1SortDirection,
};
#[cfg(target_arch = "wasm32")]
pub use transport::WorkersD1Database;
pub use transport::{D1Database, D1QueryResult, D1Statement, D1TransportError, D1Value};
