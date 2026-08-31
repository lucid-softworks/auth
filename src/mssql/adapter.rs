use crate::{
    AdapterSchemaOptions, AuthError, AuthSchemaCatalog, ResolvedAdapterSchema,
    SchemaFingerprint,
};
use bb8_tiberius::ConnectionManager;
use std::sync::{Arc, OnceLock};

pub(super) type MssqlClient = bb8_tiberius::rt::Client;

/// A Tokio/Tiberius SQL Server connection pool.
pub type MssqlPool = bb8::Pool<ConnectionManager>;

/// Better Auth MSSQL adapter options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MssqlAdapterConfig {
    /// Apply Better Auth's literal `s` suffix to resolved physical table names.
    pub use_plural: bool,
    /// Enable one SQL Server transaction for multi-operation adapter callbacks.
    pub transaction: bool,
    /// Emit query diagnostics through the crate's tracing integration.
    pub debug_logs: bool,
}

/// In-process Tiberius SQL Server backend.
#[derive(Clone)]
pub struct MssqlStore {
    pub(super) pool: MssqlPool,
    adapter_config: MssqlAdapterConfig,
    schema: Arc<OnceLock<BoundMssqlSchema>>,
}

struct BoundMssqlSchema {
    resolved: ResolvedAdapterSchema,
    physical: super::schema::MssqlSchema,
}

impl MssqlStore {
    /// Uses a caller-owned pool without changing its connection policy.
    pub fn new(pool: MssqlPool, adapter_config: MssqlAdapterConfig) -> Self {
        Self {
            pool,
            adapter_config,
            schema: Arc::new(OnceLock::new()),
        }
    }

    /// Connects to an ADO-style SQL Server connection string with BB8 defaults.
    pub async fn connect(
        connection_string: &str,
        adapter_config: MssqlAdapterConfig,
    ) -> Result<Self, AuthError> {
        let manager = ConnectionManager::build(connection_string).map_err(storage)?;
        let pool = MssqlPool::builder().build(manager).await.map_err(storage)?;
        let store = Self::new(pool, adapter_config);
        store.ready().await?;
        Ok(store)
    }

    /// Connects from a native Tiberius configuration and explicit pool size.
    pub async fn connect_with(
        config: tiberius::Config,
        max_size: u32,
        adapter_config: MssqlAdapterConfig,
    ) -> Result<Self, AuthError> {
        let manager = ConnectionManager::new(config);
        let pool = MssqlPool::builder()
            .max_size(max_size)
            .build(manager)
            .await
            .map_err(storage)?;
        let store = Self::new(pool, adapter_config);
        store.ready().await?;
        Ok(store)
    }

    /// Verifies that the pool can execute a SQL Server query.
    pub async fn ready(&self) -> Result<(), AuthError> {
        let mut connection = self.pool.get().await.map_err(storage)?;
        connection
            .simple_query("SELECT 1")
            .await
            .map_err(storage)?
            .into_row()
            .await
            .map_err(storage)?;
        Ok(())
    }

    pub fn pool(&self) -> &MssqlPool {
        &self.pool
    }

    pub fn adapter_config(&self) -> MssqlAdapterConfig {
        self.adapter_config
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
        let bound = BoundMssqlSchema {
            physical: super::schema::MssqlSchema::new(&resolved)?,
            resolved,
        };
        if let Some(bound) = self.schema.get() {
            return compare(bound.resolved.fingerprint(), &requested);
        }
        match self.schema.set(bound) {
            Ok(()) => Ok(()),
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

    pub(super) fn bind_catalog(&self, schema: Arc<AuthSchemaCatalog>) -> Result<(), AuthError> {
        self.bind_schema(schema)
    }

    pub fn resolved_schema(&self) -> Result<&ResolvedAdapterSchema, AuthError> {
        self.bound_schema().map(|schema| &schema.resolved)
    }

    /// Derives Better Auth's additive introspection plan without executing it.
    pub async fn migration_plan(
        &self,
        schema: Arc<AuthSchemaCatalog>,
        mode: super::MssqlMigrationMode,
    ) -> Result<super::MssqlMigrationPlan, super::MssqlMigrationError> {
        self.debug_operation("migration-plan", None);
        self.bind_schema(schema)
            .map_err(|error| super::MssqlMigrationError::Configuration(error.to_string()))?;
        let bound = self
            .schema
            .get()
            .ok_or_else(|| super::MssqlMigrationError::Configuration("schema is not bound".into()))?;
        super::migration::plan(&self.pool, &bound.resolved, &bound.physical, mode).await
    }

    /// Plans and executes each additive statement sequentially.
    pub async fn migrate(
        &self,
        schema: Arc<AuthSchemaCatalog>,
    ) -> Result<super::MssqlMigrationPlan, super::MssqlMigrationError> {
        let plan = self
            .migration_plan(schema, super::MssqlMigrationMode::Execute)
            .await?;
        plan.run(&self.pool).await?;
        Ok(plan)
    }

    pub(super) fn physical_schema(&self) -> Result<&super::schema::MssqlSchema, AuthError> {
        self.bound_schema().map(|schema| &schema.physical)
    }

    pub async fn insert_record(
        &self,
        model: &str,
        record: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, AuthError> {
        self.debug_operation("insert", Some(model));
        let schema = self.physical_schema()?;
        let mut connection = self.pool.get().await.map_err(storage)?;
        super::query::execute::insert(
            &mut connection,
            schema,
            model,
            record
        )
        .await
    }

    pub(super) async fn insert_required_record(
        &self,
        model: &str,
        record: serde_json::Map<String, serde_json::Value>,
    ) -> Result<serde_json::Map<String, serde_json::Value>, AuthError> {
        self.insert_record(model, record)
            .await?
            .ok_or_else(|| AuthError::Storage(format!("MSSQL insert into '{model}' returned no row")))
    }

    pub async fn find_record(
        &self,
        model: &str,
        filters: &[super::MssqlFilter],
        select: &[String],
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, AuthError> {
        self.debug_operation("find-one", Some(model));
        let schema = self.physical_schema()?;
        let mut connection = self.pool.get().await.map_err(storage)?;
        super::query::execute::find_one(
            &mut connection,
            schema,
            model,
            filters,
            select
        )
        .await
    }

    /// Finds one row and optionally applies Better Auth-compatible left joins.
    pub async fn find_record_with_options(
        &self,
        model: &str,
        filters: &[super::MssqlFilter],
        options: &super::MssqlFindOptions,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, AuthError> {
        self.debug_operation("find-one-joined", Some(model));
        let schema = self.physical_schema()?;
        let mut connection = self.pool.get().await.map_err(storage)?;
        super::query::execute::find_one_with_options(
            &mut connection,
            schema,
            model,
            filters,
            options,
        )
        .await
    }

    pub async fn find_records(
        &self,
        model: &str,
        filters: &[super::MssqlFilter],
        options: &super::MssqlFindOptions,
    ) -> Result<Vec<serde_json::Map<String, serde_json::Value>>, AuthError> {
        self.debug_operation("find-many", Some(model));
        let schema = self.physical_schema()?;
        let mut connection = self.pool.get().await.map_err(storage)?;
        super::query::execute::find_many(
            &mut connection,
            schema,
            model,
            filters,
            options
        )
        .await
    }

    pub async fn update_record(
        &self,
        model: &str,
        filters: &[super::MssqlFilter],
        values: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, AuthError> {
        self.debug_operation("update-one", Some(model));
        let schema = self.physical_schema()?;
        let mut connection = self.pool.get().await.map_err(storage)?;
        super::query::execute::update_one(
            &mut connection,
            schema,
            model,
            filters,
            values
        )
        .await
    }

    pub async fn update_records(
        &self,
        model: &str,
        filters: &[super::MssqlFilter],
        values: serde_json::Map<String, serde_json::Value>,
    ) -> Result<u64, AuthError> {
        self.debug_operation("update-many", Some(model));
        let schema = self.physical_schema()?;
        let mut connection = self.pool.get().await.map_err(storage)?;
        super::query::execute::update_many(
            &mut connection,
            schema,
            model,
            filters,
            values
        )
        .await
    }

    pub async fn count_records(
        &self,
        model: &str,
        filters: &[super::MssqlFilter],
    ) -> Result<u64, AuthError> {
        self.debug_operation("count", Some(model));
        let schema = self.physical_schema()?;
        let mut connection = self.pool.get().await.map_err(storage)?;
        super::query::execute::count(
            &mut connection,
            schema,
            model,
            filters
        )
        .await
    }

    pub async fn delete_records(
        &self,
        model: &str,
        filters: &[super::MssqlFilter],
    ) -> Result<u64, AuthError> {
        self.debug_operation("delete-many", Some(model));
        let schema = self.physical_schema()?;
        let mut connection = self.pool.get().await.map_err(storage)?;
        super::query::execute::delete_many(
            &mut connection,
            schema,
            model,
            filters
        )
        .await
    }

    pub async fn consume_record(
        &self,
        model: &str,
        filters: &[super::MssqlFilter],
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, AuthError> {
        self.debug_operation("consume-one", Some(model));
        let schema = self.physical_schema()?;
        let mut connection = self.pool.get().await.map_err(storage)?;
        super::query::execute::consume_one(
            &mut connection,
            schema,
            model,
            filters
        )
        .await
    }

    pub async fn increment_record(
        &self,
        model: &str,
        filters: &[super::MssqlFilter],
        increments: serde_json::Map<String, serde_json::Value>,
        set: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, AuthError> {
        self.debug_operation("increment-one", Some(model));
        let schema = self.physical_schema()?;
        let mut connection = self.pool.get().await.map_err(storage)?;
        super::query::execute::increment_one(
            &mut connection,
            schema,
            model,
            filters,
            increments,
            set
        )
        .await
    }

    fn bound_schema(&self) -> Result<&BoundMssqlSchema, AuthError> {
        self.schema.get().ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "MSSQL adapter schema is not bound to an AuthService".into(),
            )
        })
    }

    fn debug_operation(&self, operation: &'static str, model: Option<&str>) {
        if self.adapter_config.debug_logs {
            tracing::debug!(
                target: "lucid_auth::mssql",
                operation,
                model,
                "executing MSSQL adapter operation"
            );
        }
    }
}

fn compare(bound: &SchemaFingerprint, requested: &SchemaFingerprint) -> Result<(), AuthError> {
    if bound == requested {
        Ok(())
    } else {
        Err(AuthError::InvalidConfiguration(
            "MSSQL adapter is already bound to a different Better Auth schema".into(),
        ))
    }
}

fn storage(error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(error.to_string())
}
