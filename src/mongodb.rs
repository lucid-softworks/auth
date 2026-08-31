//! Native MongoDB persistence compatible with `@better-auth/mongo-adapter` 1.7.2.

mod access;
mod adapter;
mod agent_auth;
mod api_key;
mod codec;
mod dash;
mod device_authorization;
mod error;
mod jwt;
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

pub use adapter::{MongoAdapterConfig, MongoStore};
pub use error::{MongoAdapterError, MongoAdapterErrorCode};
pub use query::{
    MongoComparisonMode, MongoFilter, MongoFilterConnector, MongoFilterOperator,
    MongoFindOptions, MongoJoin, MongoJoinRelation, MongoSort, MongoSortDirection,
};
