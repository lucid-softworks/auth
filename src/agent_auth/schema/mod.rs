mod catalog;
mod definitions;

pub(crate) use catalog::schema_tables;
pub(crate) use definitions::AgentAuthModel;
pub use definitions::{AgentAuthModelSchema, AgentAuthSchema};

use definitions::{DEFINITIONS, FieldDefinition, ModelDefinition, Reference};
