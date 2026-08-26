//! Ordered Better Auth database schema construction and adapter resolution.

mod catalog;
mod core;
mod fingerprint;
mod generic;
mod indexes;
mod resolver;

pub(crate) use catalog::remap_plugin_table;
pub use catalog::{
    AuthSchemaCatalog, DatabaseIdType, DatabaseModelSchema, DatabaseSchemaIndex, PluginSchemaTable,
    SchemaFingerprint, SchemaTable,
};
pub use generic::{GenericDatabaseSchema, GenericSchemaTable};
pub use indexes::{ResolvedDatabaseIndex, SchemaIndexError};
pub use resolver::{AdapterSchemaOptions, ResolvedAdapterSchema, SchemaResolutionError};
