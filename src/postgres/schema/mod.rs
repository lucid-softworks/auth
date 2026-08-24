use super::{PostgresStore, migrate::core_migrations, plugin::validate_migrations};
use crate::{AuthError, PluginMigrationContribution};
use serde::Serialize;
use sha2::{Digest, Sha256};

mod catalog;
mod diagnostics;
mod parser;

use parser::SchemaManifest;

/// One physical PostgreSQL object derived from the ordered migration SQL.
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

/// Stable identifier and fingerprint for a core or enabled-plugin migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "owner", rename_all = "camelCase")]
pub enum PostgresMigrationDescriptor {
    Core {
        version: i64,
        description: String,
        checksum: String,
    },
    Plugin {
        plugin_id: String,
        migration_id: String,
        description: String,
        checksum: String,
    },
}

/// Deterministic migration and final-schema plan for one enabled plugin set.
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
    UnknownCoreMigration {
        version: i64,
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
    pub fn new(plugin_migrations: &[PluginMigrationContribution]) -> Result<Self, AuthError> {
        validate_migrations(plugin_migrations)?;
        let mut migrations = Vec::new();
        let mut manifest = SchemaManifest::default();
        for migration in core_migrations() {
            migrations.push(PostgresMigrationDescriptor::Core {
                version: migration.version,
                description: migration.description.into(),
                checksum: migration_checksum(migration.sql),
            });
            manifest.apply(migration.sql);
        }
        for contribution in plugin_migrations {
            migrations.push(PostgresMigrationDescriptor::Plugin {
                plugin_id: contribution.plugin_id.into(),
                migration_id: contribution.migration.id.to_string(),
                description: contribution.migration.description.to_string(),
                checksum: migration_checksum(contribution.migration.sql.as_ref()),
            });
            manifest.apply(contribution.migration.sql.as_ref());
        }
        manifest.add_bookkeeping(!plugin_migrations.is_empty());
        Ok(Self {
            migrations,
            schema: manifest.objects(),
        })
    }
}

impl PostgresStore {
    /// Discovers the deterministic core and enabled-plugin migration/schema plan.
    pub fn migration_plan(
        plugin_migrations: &[PluginMigrationContribution],
    ) -> Result<PostgresMigrationPlan, AuthError> {
        PostgresMigrationPlan::new(plugin_migrations)
    }

    /// Applies core and plugin migrations and returns a clean-schema report.
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
        let plan = PostgresMigrationPlan::new(plugin_migrations)?;
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
    use crate::{PluginMigration, PluginMigrationContribution};

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
        let left = PostgresMigrationPlan::new(&migrations).unwrap();
        let right = PostgresMigrationPlan::new(&migrations).unwrap();
        assert_eq!(left, right);
        assert!(left.schema.contains(&PostgresSchemaObject::Column {
            table: "lucid_auth_example_records".into(),
            name: "value".into(),
            data_type: "text".into(),
        }));
        assert!(left.schema.contains(&PostgresSchemaObject::Index {
            table: "lucid_auth_example_records".into(),
            name: "lucid_auth_example_records_id_idx".into(),
            unique: true,
        }));
    }

    #[test]
    fn built_in_migrations_generate_the_current_core_shape() {
        let plan = PostgresMigrationPlan::new(&[]).unwrap();
        assert!(plan.schema.contains(&PostgresSchemaObject::Column {
            table: "lucid_auth_rate_limits".into(),
            name: "count".into(),
            data_type: "bigint".into(),
        }));
        assert!(!plan.schema.iter().any(|object| matches!(
            object,
            PostgresSchemaObject::Column { table, name, .. }
                if table == "lucid_auth_rate_limits" && name == "expires_at"
        )));
    }
}
