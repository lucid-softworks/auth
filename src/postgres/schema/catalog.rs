use super::super::{PostgresStore, storage_error};
use crate::AuthError;
use std::collections::BTreeMap;

pub(super) struct Catalog {
    pub(super) columns: BTreeMap<(String, String), String>,
    pub(super) indexes: BTreeMap<(String, String), bool>,
    pub(super) core_migrations: Vec<AppliedCoreMigration>,
    pub(super) plugin_migrations: Vec<AppliedPluginMigration>,
}

pub(super) struct AppliedCoreMigration {
    pub(super) version: i64,
    pub(super) description: String,
    pub(super) checksum: Option<String>,
}

pub(super) struct AppliedPluginMigration {
    pub(super) plugin_id: String,
    pub(super) migration_id: String,
    pub(super) description: String,
    pub(super) checksum: Option<String>,
}

impl PostgresStore {
    pub(super) async fn load_schema_catalog(&self) -> Result<Catalog, AuthError> {
        let columns = load_columns(&self.pool).await?;
        let indexes = load_indexes(&self.pool).await?;
        let core_migrations = load_core_migrations(&self.pool, &columns).await?;
        let plugin_migrations = load_plugin_migrations(&self.pool, &columns).await?;
        Ok(Catalog {
            columns,
            indexes,
            core_migrations,
            plugin_migrations,
        })
    }
}

async fn load_columns(
    pool: &sqlx::PgPool,
) -> Result<BTreeMap<(String, String), String>, AuthError> {
    sqlx::query_as::<_, (String, String, String)>(
        "SELECT table_name, column_name, data_type \
         FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name LIKE 'lucid_auth_%'",
    )
    .fetch_all(pool)
    .await
    .map_err(storage_error)
    .map(|rows| {
        rows.into_iter()
            .map(|(table, column, data_type)| ((table, column), data_type))
            .collect()
    })
}

async fn load_indexes(pool: &sqlx::PgPool) -> Result<BTreeMap<(String, String), bool>, AuthError> {
    sqlx::query_as::<_, (String, String, bool)>(
        "SELECT table_class.relname, index_class.relname, pg_index.indisunique \
         FROM pg_index \
         JOIN pg_class AS table_class ON table_class.oid = pg_index.indrelid \
         JOIN pg_class AS index_class ON index_class.oid = pg_index.indexrelid \
         JOIN pg_namespace ON pg_namespace.oid = table_class.relnamespace \
         WHERE pg_namespace.nspname = current_schema() \
           AND table_class.relname LIKE 'lucid_auth_%'",
    )
    .fetch_all(pool)
    .await
    .map_err(storage_error)
    .map(|rows| {
        rows.into_iter()
            .map(|(table, index, unique)| ((table, index), unique))
            .collect()
    })
}

async fn load_core_migrations(
    pool: &sqlx::PgPool,
    columns: &BTreeMap<(String, String), String>,
) -> Result<Vec<AppliedCoreMigration>, AuthError> {
    if !table_exists(pool, "lucid_auth_migrations").await? {
        return Ok(Vec::new());
    }
    let has_checksum = columns.contains_key(&("lucid_auth_migrations".into(), "checksum".into()));
    let sql = if has_checksum {
        "SELECT version, description, checksum FROM lucid_auth_migrations ORDER BY version"
    } else {
        "SELECT version, description, NULL::TEXT FROM lucid_auth_migrations ORDER BY version"
    };
    sqlx::query_as::<_, (i64, String, Option<String>)>(sql)
        .fetch_all(pool)
        .await
        .map_err(storage_error)
        .map(|rows| {
            rows.into_iter()
                .map(|(version, description, checksum)| AppliedCoreMigration {
                    version,
                    description,
                    checksum,
                })
                .collect()
        })
}

async fn load_plugin_migrations(
    pool: &sqlx::PgPool,
    columns: &BTreeMap<(String, String), String>,
) -> Result<Vec<AppliedPluginMigration>, AuthError> {
    if !table_exists(pool, "lucid_auth_plugin_migrations").await? {
        return Ok(Vec::new());
    }
    let has_checksum =
        columns.contains_key(&("lucid_auth_plugin_migrations".into(), "checksum".into()));
    let sql = if has_checksum {
        "SELECT plugin_id, migration_id, description, checksum \
         FROM lucid_auth_plugin_migrations ORDER BY plugin_id, migration_id"
    } else {
        "SELECT plugin_id, migration_id, description, NULL::TEXT \
         FROM lucid_auth_plugin_migrations ORDER BY plugin_id, migration_id"
    };
    sqlx::query_as::<_, (String, String, String, Option<String>)>(sql)
        .fetch_all(pool)
        .await
        .map_err(storage_error)
        .map(|rows| {
            rows.into_iter()
                .map(
                    |(plugin_id, migration_id, description, checksum)| AppliedPluginMigration {
                        plugin_id,
                        migration_id,
                        description,
                        checksum,
                    },
                )
                .collect()
        })
}

async fn table_exists(pool: &sqlx::PgPool, table: &str) -> Result<bool, AuthError> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (\
           SELECT 1 FROM information_schema.tables \
           WHERE table_schema = current_schema() AND table_name = $1\
         )",
    )
    .bind(table)
    .fetch_one(pool)
    .await
    .map_err(storage_error)
}
