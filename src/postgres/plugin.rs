use super::{PostgresStore, schema::migration_checksum, storage_error};
use crate::{AuthError, PluginMigrationContribution};
use std::collections::{BTreeSet, HashSet};

const USER_TABLE_PLACEHOLDER: &str = "\x7b\x7blucid-auth:user-table\x7d\x7d";
const SESSION_TABLE_PLACEHOLDER: &str = "\x7b\x7blucid-auth:session-table\x7d\x7d";
const PLACEHOLDER_PREFIX: &str = "\x7b\x7blucid-auth:";

impl PostgresStore {
    /// Applies validated plugin migrations under the same advisory lock used
    /// by core migrations. Each `(plugin_id, migration_id)` runs once.
    pub async fn migrate_plugins(
        &self,
        migrations: &[PluginMigrationContribution],
    ) -> Result<(), AuthError> {
        let schema = self.resolved_schema()?;
        validate_migrations(migrations)?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        prepare_table(&mut transaction).await?;
        for contribution in migrations {
            apply_migration(&mut transaction, contribution, schema).await?;
        }
        reject_unknown_enabled_migrations(&mut transaction, migrations).await?;
        transaction.commit().await.map_err(storage_error)
    }
}

async fn prepare_table(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), AuthError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('lucid-auth-migrations'))")
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS lucid_auth_plugin_migrations (\
               plugin_id TEXT NOT NULL, \
               migration_id TEXT NOT NULL, \
               description TEXT NOT NULL, \
               checksum TEXT, \
               applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
               PRIMARY KEY (plugin_id, migration_id)\
             )",
    )
    .execute(&mut **transaction)
    .await
    .map_err(storage_error)?;
    sqlx::query(
        "ALTER TABLE lucid_auth_plugin_migrations \
             ADD COLUMN IF NOT EXISTS checksum TEXT",
    )
    .execute(&mut **transaction)
    .await
    .map_err(storage_error)?;
    Ok(())
}

async fn apply_migration(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    contribution: &PluginMigrationContribution,
    schema: &crate::ResolvedAdapterSchema,
) -> Result<(), AuthError> {
    let applied = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT description, checksum FROM lucid_auth_plugin_migrations \
         WHERE plugin_id = $1 AND migration_id = $2",
    )
    .bind(contribution.plugin_id)
    .bind(contribution.migration.id.as_ref())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(storage_error)?;
    let sql = resolve_catalog_placeholders(contribution.migration.sql.as_ref(), schema)?;
    let checksum = migration_checksum(&sql);
    if let Some(applied) = applied {
        return validate_applied(transaction, contribution, applied, &checksum).await;
    }
    sqlx::raw_sql(&sql)
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
    sqlx::query(
        "INSERT INTO lucid_auth_plugin_migrations \
         (plugin_id, migration_id, description, checksum) VALUES ($1, $2, $3, $4)",
    )
    .bind(contribution.plugin_id)
    .bind(contribution.migration.id.as_ref())
    .bind(contribution.migration.description.as_ref())
    .bind(checksum)
    .execute(&mut **transaction)
    .await
    .map_err(storage_error)?;
    Ok(())
}

pub(super) fn resolve_catalog_placeholders(
    sql: &str,
    schema: &crate::ResolvedAdapterSchema,
) -> Result<String, AuthError> {
    let mut resolved = sql.to_owned();
    for (placeholder, logical) in [
        (USER_TABLE_PLACEHOLDER, "user"),
        (SESSION_TABLE_PLACEHOLDER, "session"),
    ] {
        if !resolved.contains(placeholder) {
            continue;
        }
        let table = schema
            .model_name(logical)
            .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?;
        resolved = resolved.replace(placeholder, &quote_identifier(&table));
    }
    if resolved.contains(PLACEHOLDER_PREFIX) {
        return Err(AuthError::InvalidConfiguration(
            "plugin migration contains an unknown lucid-auth schema placeholder".into(),
        ));
    }
    Ok(resolved)
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

async fn validate_applied(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    contribution: &PluginMigrationContribution,
    (description, checksum): (String, Option<String>),
    expected_checksum: &str,
) -> Result<(), AuthError> {
    let id = format!("{}:{}", contribution.plugin_id, contribution.migration.id);
    if description != contribution.migration.description {
        return Err(invalid(format!(
            "plugin migration '{id}' description does not match this binary"
        )));
    }
    match checksum {
        Some(actual) if actual != expected_checksum => Err(invalid(format!(
            "plugin migration '{id}' checksum does not match this binary"
        ))),
        None => {
            sqlx::query(
                "UPDATE lucid_auth_plugin_migrations SET checksum = $3 \
                 WHERE plugin_id = $1 AND migration_id = $2",
            )
            .bind(contribution.plugin_id)
            .bind(contribution.migration.id.as_ref())
            .bind(expected_checksum)
            .execute(&mut **transaction)
            .await
            .map_err(storage_error)?;
            Ok(())
        }
        Some(_) => Ok(()),
    }
}

pub(super) fn validate_migrations(
    migrations: &[PluginMigrationContribution],
) -> Result<(), AuthError> {
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
        if !keys.insert((contribution.plugin_id, contribution.migration.id.as_ref())) {
            return Err(AuthError::InvalidConfiguration(format!(
                "plugin migration '{}:{}' is duplicated",
                contribution.plugin_id, contribution.migration.id
            )));
        }
    }
    Ok(())
}

async fn reject_unknown_enabled_migrations(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    migrations: &[PluginMigrationContribution],
) -> Result<(), AuthError> {
    let expected = migrations
        .iter()
        .map(|migration| (migration.plugin_id, migration.migration.id.as_ref()))
        .collect::<BTreeSet<_>>();
    let enabled = expected
        .iter()
        .map(|(plugin_id, _)| *plugin_id)
        .collect::<BTreeSet<_>>();
    let applied = sqlx::query_as::<_, (String, String)>(
        "SELECT plugin_id, migration_id FROM lucid_auth_plugin_migrations",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(storage_error)?;
    for (plugin_id, migration_id) in applied {
        if enabled.contains(plugin_id.as_str())
            && !expected.contains(&(plugin_id.as_str(), migration_id.as_str()))
        {
            return Err(invalid(format!(
                "database contains unknown migration '{plugin_id}:{migration_id}' for an enabled plugin"
            )));
        }
    }
    Ok(())
}

fn invalid(message: String) -> AuthError {
    AuthError::InvalidConfiguration(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdapterSchemaOptions, AuthConfig, AuthSchemaCatalog, ResolvedAdapterSchema};
    use std::sync::Arc;

    #[test]
    fn lucid_extension_placeholders_use_quoted_bound_plural_tables() {
        let mut config = AuthConfig::new([19; 32]).unwrap();
        config.user.model_name = Some("people \"raw".into());
        config.session.model_name = Some("login rows".into());
        let schema = ResolvedAdapterSchema::new(
            Arc::new(AuthSchemaCatalog::build(&config, []).unwrap()),
            AdapterSchemaOptions { use_plural: true },
        )
        .unwrap();
        let source = format!(
            "REFERENCES {USER_TABLE_PLACEHOLDER}(id); REFERENCES {SESSION_TABLE_PLACEHOLDER}(id)"
        );
        let sql = resolve_catalog_placeholders(&source, &schema).unwrap();
        assert_eq!(
            sql,
            "REFERENCES \"people \"\"raws\"(id); REFERENCES \"login rowss\"(id)"
        );
    }
}
