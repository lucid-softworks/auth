use super::{PostgresStore, storage_error};
use crate::{AuthError, PluginMigrationContribution};
use std::collections::HashSet;

impl PostgresStore {
    /// Applies validated plugin migrations under the same advisory lock used
    /// by core migrations. Each `(plugin_id, migration_id)` runs once.
    pub async fn migrate_plugins(
        &self,
        migrations: &[PluginMigrationContribution],
    ) -> Result<(), AuthError> {
        validate_migrations(migrations)?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('lucid-auth-migrations'))")
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS lucid_auth_plugin_migrations (\
               plugin_id TEXT NOT NULL, \
               migration_id TEXT NOT NULL, \
               description TEXT NOT NULL, \
               applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
               PRIMARY KEY (plugin_id, migration_id)\
             )",
        )
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;

        for contribution in migrations {
            let applied = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM lucid_auth_plugin_migrations \
                 WHERE plugin_id = $1 AND migration_id = $2)",
            )
            .bind(contribution.plugin_id)
            .bind(contribution.migration.id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(storage_error)?;
            if applied {
                continue;
            }
            sqlx::raw_sql(contribution.migration.sql)
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
            sqlx::query(
                "INSERT INTO lucid_auth_plugin_migrations \
                 (plugin_id, migration_id, description) VALUES ($1, $2, $3)",
            )
            .bind(contribution.plugin_id)
            .bind(contribution.migration.id)
            .bind(contribution.migration.description)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        }
        transaction.commit().await.map_err(storage_error)
    }
}

fn validate_migrations(migrations: &[PluginMigrationContribution]) -> Result<(), AuthError> {
    let mut keys = HashSet::new();
    for contribution in migrations {
        if contribution.plugin_id.is_empty()
            || contribution.migration.id.is_empty()
            || contribution.migration.description.trim().is_empty()
            || contribution.migration.sql.trim().is_empty()
        {
            return Err(AuthError::InvalidConfiguration(
                "plugin migration metadata is incomplete".into(),
            ));
        }
        if !keys.insert((contribution.plugin_id, contribution.migration.id)) {
            return Err(AuthError::InvalidConfiguration(format!(
                "plugin migration '{}:{}' is duplicated",
                contribution.plugin_id, contribution.migration.id
            )));
        }
    }
    Ok(())
}
