use super::{PostgresStore, plugin::validate_migrations};
use crate::{AuthError, PluginMigrationContribution};
use serde::Serialize;
use sha2::{Digest, Sha256};

mod catalog;
mod diagnostics;

/// One physical PostgreSQL object derived from the bound adapter schema.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum PostgresSchemaObject {
    Column {
        table: String,
        name: String,
        data_type: String,
    },
    Index {
        table: String,
        name: String,
        unique: bool,
    },
    Table {
        name: String,
    },
}

/// Stable identifier and fingerprint for an enabled Lucid extension operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "owner", rename_all = "camelCase")]
pub enum PostgresMigrationDescriptor {
    Plugin {
        plugin_id: String,
        migration_id: String,
        description: String,
        checksum: String,
    },
}

/// Deterministic physical-schema and extension-operation plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostgresMigrationPlan {
    pub migrations: Vec<PostgresMigrationDescriptor>,
    pub schema: Vec<PostgresSchemaObject>,
}

/// A database difference that cannot be repaired merely by applying a pending migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum PostgresSchemaIssue {
    ColumnTypeMismatch {
        table: String,
        column: String,
        expected: String,
        actual: String,
    },
    DescriptionMismatch {
        migration: String,
        expected: String,
        actual: String,
    },
    IndexUniquenessMismatch {
        table: String,
        index: String,
        expected: bool,
        actual: bool,
    },
    MigrationChecksumMismatch {
        migration: String,
        expected: String,
        actual: String,
    },
    MigrationChecksumMissing {
        migration: String,
    },
    MissingColumn {
        table: String,
        column: String,
    },
    MissingIndex {
        table: String,
        index: String,
    },
    MissingTable {
        table: String,
    },
    UnknownEnabledPluginMigration {
        plugin_id: String,
        migration_id: String,
    },
}

/// Secret-free comparison between a migration plan and the current PostgreSQL schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostgresSchemaReport {
    pub compatible: bool,
    pub pending_migrations: Vec<String>,
    pub issues: Vec<PostgresSchemaIssue>,
}

impl PostgresMigrationPlan {
    fn new(
        schema: Vec<PostgresSchemaObject>,
        plugin_migrations: &[PluginMigrationContribution],
        resolved_schema: &crate::ResolvedAdapterSchema,
    ) -> Result<Self, AuthError> {
        validate_migrations(plugin_migrations)?;
        let migrations = plugin_migrations
            .iter()
            .map(|contribution| {
                let sql = super::plugin::resolve_catalog_placeholders(
                    contribution.migration.sql.as_ref(),
                    resolved_schema,
                )?;
                Ok(PostgresMigrationDescriptor::Plugin {
                    plugin_id: contribution.plugin_id.into(),
                    migration_id: contribution.migration.id.to_string(),
                    description: contribution.migration.description.to_string(),
                    checksum: migration_checksum(&sql),
                })
            })
            .collect::<Result<Vec<_>, AuthError>>()?;
        Ok(Self { migrations, schema })
    }
}

impl PostgresStore {
    /// Discovers the deterministic bound-schema and extension-operation plan.
    pub fn migration_plan(
        &self,
        plugin_migrations: &[PluginMigrationContribution],
    ) -> Result<PostgresMigrationPlan, AuthError> {
        let schema = self.resolved_schema()?;
        let objects = self.physical_schema()?.schema_objects(schema);
        PostgresMigrationPlan::new(objects, plugin_migrations, schema)
    }

    /// Evolves the bound schema, applies extension operations, and reports drift.
    pub async fn migrate_all(
        &self,
        plugin_migrations: &[PluginMigrationContribution],
    ) -> Result<PostgresSchemaReport, AuthError> {
        self.migrate().await?;
        self.migrate_plugins(plugin_migrations).await?;
        self.diagnose_schema(plugin_migrations).await
    }

    /// Compares the current catalog and recorded fingerprints without mutation.
    pub async fn diagnose_schema(
        &self,
        plugin_migrations: &[PluginMigrationContribution],
    ) -> Result<PostgresSchemaReport, AuthError> {
        let plan = self.migration_plan(plugin_migrations)?;
        let catalog = self.load_schema_catalog().await?;
        Ok(diagnostics::compare(&plan, &catalog))
    }
}

pub(super) fn migration_checksum(sql: &str) -> String {
    hex::encode(Sha256::digest(sql.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdapterSchemaOptions, AuthConfig, AuthSchemaCatalog, PluginMigration,
        PluginMigrationContribution, ResolvedAdapterSchema,
    };
    use std::sync::Arc;

    #[test]
    fn plans_are_deterministic_and_derive_plugin_schema() {
        let migrations = [PluginMigrationContribution {
            plugin_id: "example",
            migration: PluginMigration::owned(
                String::from("records"),
                String::from("example records"),
                String::from(
                    "CREATE TABLE lucid_auth_example_records (id UUID, value TEXT); \
                     CREATE UNIQUE INDEX lucid_auth_example_records_id_idx \
                     ON lucid_auth_example_records(id);",
                ),
            ),
        }];
        let schema = vec![PostgresSchemaObject::Column {
            table: "example".into(),
            name: "value".into(),
            data_type: "text".into(),
        }];
        let config = AuthConfig::new([18; 32]).unwrap();
        let resolved = ResolvedAdapterSchema::new(
            Arc::new(AuthSchemaCatalog::build(&config, []).unwrap()),
            AdapterSchemaOptions::default(),
        )
        .unwrap();
        let left = PostgresMigrationPlan::new(schema.clone(), &migrations, &resolved).unwrap();
        let right = PostgresMigrationPlan::new(schema, &migrations, &resolved).unwrap();
        assert_eq!(left, right);
        assert!(left.schema.contains(&PostgresSchemaObject::Column {
            table: "example".into(),
            name: "value".into(),
            data_type: "text".into(),
        }));
        assert_eq!(left.migrations.len(), 1);
    }
}
