use super::schema::SqliteSchema;
use crate::{
    AdapterSchemaOptions, AuthError, AuthSchemaCatalog, ResolvedAdapterSchema, SchemaFingerprint,
};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use std::sync::{Arc, OnceLock};

/// Better Auth SQLite adapter schema options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SqliteAdapterConfig {
    /// Apply Better Auth's literal `s` suffix to resolved physical table names.
    pub use_plural: bool,
}

/// In-process SQLx local SQLite backend.
///
/// A plain `:memory:` database belongs to one connection. Configure the
/// supplied pool with one connection unless the URL explicitly selects a
/// shared-memory database.
#[derive(Clone)]
pub struct SqliteStore {
    pub(super) pool: SqlitePool,
    adapter_config: SqliteAdapterConfig,
    schema: Arc<OnceLock<Arc<BoundSqliteSchema>>>,
}

pub(super) struct BoundSqliteSchema {
    pub(super) resolved: ResolvedAdapterSchema,
    pub(super) physical: SqliteSchema,
}

impl SqliteStore {
    /// Uses an existing pool without changing any connection pragma.
    pub fn new(pool: SqlitePool, adapter_config: SqliteAdapterConfig) -> Self {
        Self {
            pool,
            adapter_config,
            schema: Arc::new(OnceLock::new()),
        }
    }

    /// Connects through SQLx defaults without imposing SQLite runtime policy.
    pub async fn connect(
        database_url: &str,
        adapter_config: SqliteAdapterConfig,
    ) -> Result<Self, sqlx::Error> {
        SqlitePool::connect(database_url)
            .await
            .map(|pool| Self::new(pool, adapter_config))
    }

    /// Connects with caller-constructed pool and SQLite connection options.
    pub async fn connect_with(
        pool_options: SqlitePoolOptions,
        connect_options: sqlx::sqlite::SqliteConnectOptions,
        adapter_config: SqliteAdapterConfig,
    ) -> Result<Self, sqlx::Error> {
        pool_options
            .connect_with(connect_options)
            .await
            .map(|pool| Self::new(pool, adapter_config))
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub(super) fn bound_schema(&self) -> Result<&BoundSqliteSchema, AuthError> {
        self.schema.get().map(Arc::as_ref).ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "SQLite adapter schema is not bound to an AuthService".into(),
            )
        })
    }

    pub(super) fn physical_schema(&self) -> Result<&SqliteSchema, AuthError> {
        self.bound_schema().map(|schema| &schema.physical)
    }

    pub(crate) fn bind_catalog(&self, schema: Arc<AuthSchemaCatalog>) -> Result<(), AuthError> {
        let resolved = ResolvedAdapterSchema::new(
            schema,
            AdapterSchemaOptions {
                use_plural: self.adapter_config.use_plural,
            },
        )
        .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?;
        let requested_fingerprint = resolved.fingerprint().clone();
        let bound = Arc::new(BoundSqliteSchema {
            physical: SqliteSchema::new(&resolved)?,
            resolved,
        });
        if let Some(existing) = self.schema.get() {
            return compare(existing.resolved.fingerprint(), &requested_fingerprint);
        }
        match self.schema.set(bound) {
            Ok(()) => Ok(()),
            Err(_) => compare(
                self.schema
                    .get()
                    .expect("a failed OnceLock set has a winning value")
                    .resolved
                    .fingerprint(),
                &requested_fingerprint,
            ),
        }
    }

    /// Derives an additive Better Auth 1.7.1 migration plan from live SQLite
    /// metadata. Planning does not execute SQL.
    pub async fn migration_plan(
        &self,
        schema: Arc<AuthSchemaCatalog>,
        mode: crate::sqlite::SqliteMigrationMode,
    ) -> Result<crate::sqlite::SqliteMigrationPlan, crate::sqlite::SqliteMigrationError> {
        self.bind_catalog(schema).map_err(|error| {
            crate::sqlite::SqliteMigrationError::Configuration(error.to_string())
        })?;
        let bound = self.bound_schema().map_err(|error| {
            crate::sqlite::SqliteMigrationError::Configuration(error.to_string())
        })?;
        crate::sqlite::migration::plan(&self.pool, &bound.resolved, &bound.physical, mode).await
    }

    /// Plans and executes each additive statement sequentially, matching the
    /// pinned runner. No ledger or all-plan transaction is introduced.
    pub async fn migrate(
        &self,
        schema: Arc<AuthSchemaCatalog>,
    ) -> Result<crate::sqlite::SqliteMigrationPlan, crate::sqlite::SqliteMigrationError> {
        let plan = self
            .migration_plan(schema, crate::sqlite::SqliteMigrationMode::Execute)
            .await?;
        plan.run(&self.pool).await?;
        Ok(plan)
    }
}

fn compare(bound: &SchemaFingerprint, requested: &SchemaFingerprint) -> Result<(), AuthError> {
    if bound == requested {
        Ok(())
    } else {
        Err(AuthError::InvalidConfiguration(
            "SQLite adapter is already bound to a different Better Auth schema".into(),
        ))
    }
}
