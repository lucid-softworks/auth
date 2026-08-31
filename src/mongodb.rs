//! Native MongoDB persistence compatible with `@better-auth/mongo-adapter` 1.7.1.

mod adapter;
mod error;
mod query;
mod schema;
mod value;

pub use adapter::{MongoAdapterConfig, MongoStore};
pub use error::{MongoAdapterError, MongoAdapterErrorCode};
pub use query::{
    MongoComparisonMode, MongoFilter, MongoFilterConnector, MongoFilterOperator,
    MongoFindOptions, MongoJoin, MongoJoinRelation, MongoSort, MongoSortDirection,
};
