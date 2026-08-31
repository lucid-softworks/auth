use crate::{
    AdapterSchemaOptions, AuthError, AuthSchemaCatalog, ResolvedAdapterSchema,
    SchemaFingerprint,
};
use sqlx::{MySqlPool, mysql::MySqlPoolOptions};
use std::sync::{Arc, OnceLock};

/// Better Auth MySQL adapter schema options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MySqlAdapterConfig {
    /// Apply Better Auth's literal `s` suffix to resolved physical table names.
    pub use_plural: bool,
}

/// In-process SQLx MySQL backend.
#[derive(Clone)]
pub struct MySqlStore {
    pub(super) pool: MySqlPool,
    adapter_config: MySqlAdapterConfig,
    schema: Arc<OnceLock<BoundMySqlSchema>>,
}

struct BoundMySqlSchema {
    resolved: ResolvedAdapterSchema,
    physical: super::schema::MySqlSchema,
}

impl MySqlStore {
    /// Uses a caller-owned pool without changing its connection policy.
    ///
    /// Call [`Self::ready`] during startup before serving authentication.
    pub fn new(pool: MySqlPool, adapter_config: MySqlAdapterConfig) -> Self {
        Self {
            pool,
            adapter_config,
            schema: Arc::new(OnceLock::new()),
        }
    }

    /// Connects through SQLx's MySQL defaults and verifies the UTC invariant.
    pub async fn connect(
        database_url: &str,
        adapter_config: MySqlAdapterConfig,
    ) -> Result<Self, AuthError> {
        let pool = MySqlPool::connect(database_url).await.map_err(storage)?;
        let store = Self::new(pool, adapter_config);
        store.ready().await?;
        Ok(store)
    }

    /// Connects with caller-constructed pool and connection options.
    pub async fn connect_with(
        pool_options: MySqlPoolOptions,
        connect_options: sqlx::mysql::MySqlConnectOptions,
        adapter_config: MySqlAdapterConfig,
    ) -> Result<Self, AuthError> {
        let pool = pool_options
            .connect_with(connect_options)
            .await
            .map_err(storage)?;
        let store = Self::new(pool, adapter_config);
        store.ready().await?;
        Ok(store)
    }

    /// Rejects pools whose session timezone would skew UTC date persistence.
    pub async fn ready(&self) -> Result<(), AuthError> {
        let timezone = sqlx::query_scalar::<_, String>("select @@session.time_zone")
            .fetch_one(&self.pool)
            .await
            .map_err(storage)?;
        if timezone == "+00:00" {
            return Ok(());
        }
        Err(AuthError::InvalidConfiguration(format!(
            "MySQL session timezone must be +00:00 for Better Auth UTC dates; found {timezone}"
        )))
    }

    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }

    /// Binds the complete resolved Better Auth schema exactly once.
    pub fn bind_schema(&self, schema: Arc<AuthSchemaCatalog>) -> Result<(), AuthError> {
        let resolved = ResolvedAdapterSchema::new(
            schema,
            AdapterSchemaOptions {
                use_plural: self.adapter_config.use_plural,
            },
        )
        .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?;
        let requested = resolved.fingerprint().clone();
        let database_generated_ids = resolved.catalog().id_generation()
            == crate::DatabaseIdGenerationKind::Database;
        let bound = BoundMySqlSchema {
            physical: super::schema::MySqlSchema::new(&resolved)?,
            resolved,
        };
        if let Some(bound) = self.schema.get() {
            return compare(bound.resolved.fingerprint(), &requested);
        }
        match self.schema.set(bound) {
            Ok(()) => {
                if database_generated_ids {
                    tracing::warn!(
                        "[Kysely Adapter] MySQL does not support INSERT...RETURNING. With generateId set to false, the adapter uses best-effort fallback strategies (unique columns, full-field match) to retrieve inserted rows. For reliable behavior, use Better Auth's default ID generation, a custom generateId function, or generateId: \"serial\" for auto-increment."
                    );
                }
                Ok(())
            }
            Err(_) => compare(
                self.schema
                    .get()
                    .expect("a failed OnceLock set has a winning value")
                    .resolved
                    .fingerprint(),
                &requested,
            ),
        }
    }

    /// Returns the bound shared schema descriptor.
    pub fn resolved_schema(&self) -> Result<&ResolvedAdapterSchema, AuthError> {
        self.bound_schema().map(|schema| &schema.resolved)
    }

    /// Derives an additive Better Auth 1.7.1 migration plan from live MySQL
    /// metadata without executing it.
    pub async fn migration_plan(
        &self,
        schema: Arc<AuthSchemaCatalog>,
        mode: crate::mysql::MySqlMigrationMode,
    ) -> Result<crate::mysql::MySqlMigrationPlan, crate::mysql::MySqlMigrationError> {
        self.bind_schema(schema).map_err(|error| {
            crate::mysql::MySqlMigrationError::Configuration(error.to_string())
        })?;
        let bound = self.bound_schema().map_err(|error| {
            crate::mysql::MySqlMigrationError::Configuration(error.to_string())
        })?;
        crate::mysql::migration::plan(&self.pool, &bound.resolved, &bound.physical, mode).await
    }

    /// Plans and executes each additive statement sequentially.
    pub async fn migrate(
        &self,
        schema: Arc<AuthSchemaCatalog>,
    ) -> Result<crate::mysql::MySqlMigrationPlan, crate::mysql::MySqlMigrationError> {
        let plan = self
            .migration_plan(schema, crate::mysql::MySqlMigrationMode::Execute)
            .await?;
        plan.run(&self.pool).await?;
        Ok(plan)
    }

    pub(super) fn physical_schema(&self) -> Result<&super::schema::MySqlSchema, AuthError> {
        self.bound_schema().map(|schema| &schema.physical)
    }

    fn bound_schema(&self) -> Result<&BoundMySqlSchema, AuthError> {
        self.schema.get().ok_or_else(|| {
            AuthError::InvalidConfiguration("MySQL adapter schema is not bound to an AuthService".into())
        })
    }
}

fn compare(bound: &SchemaFingerprint, requested: &SchemaFingerprint) -> Result<(), AuthError> {
    if bound == requested {
        Ok(())
    } else {
        Err(AuthError::InvalidConfiguration(
            "MySQL adapter is already bound to a different Better Auth schema".into(),
        ))
    }
}

fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
