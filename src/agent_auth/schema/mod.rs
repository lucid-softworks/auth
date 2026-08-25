mod definitions;
mod migration;
mod resolution;

pub(crate) use definitions::AgentAuthModel;
pub use definitions::{AgentAuthModelSchema, AgentAuthSchema};
pub use resolution::AgentAuthSchemaError;
#[cfg(feature = "postgres")]
pub(crate) use resolution::ResolvedAgentAuthModel;
pub(crate) use resolution::ResolvedAgentAuthSchema;

use definitions::{DEFINITIONS, ModelDefinition, Reference};

use crate::PluginMigration;

pub(crate) fn migration(schema: &AgentAuthSchema) -> Result<PluginMigration, AgentAuthSchemaError> {
    let resolved = ResolvedAgentAuthSchema::new(schema)?;
    let default = ResolvedAgentAuthSchema::new(&AgentAuthSchema::default())?;
    let id = if resolved.fingerprint() == default.fingerprint() {
        "better-auth-agent-auth-schema".to_owned()
    } else {
        format!("better-auth-agent-auth-schema-{}", resolved.fingerprint())
    };
    Ok(PluginMigration::owned(
        id,
        "Better Auth 1.7.1 Agent Auth schema",
        resolved.migration_sql(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_and_custom_migrations_have_stable_distinct_ids() {
        let default = migration(&AgentAuthSchema::default()).unwrap();
        assert_eq!(default.id.as_ref(), "better-auth-agent-auth-schema");

        let mut custom = AgentAuthSchema::default();
        custom.agent.model_name = Some("custom_agents".into());
        let first = migration(&custom).unwrap();
        let second = migration(&custom).unwrap();
        assert_eq!(first.id, second.id);
        assert_ne!(first.id, default.id);
        assert!(first.id.starts_with("better-auth-agent-auth-schema-"));
    }
}
