use crate::{
    AdapterSchemaOptions, AuthError, AuthSchemaCatalog, ResolvedAdapterSchema,
    SchemaFingerprint,
};
use bb8_tiberius::ConnectionManager;
use std::sync::{Arc, OnceLock};

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
    schema: Arc<OnceLock<ResolvedAdapterSchema>>,
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
        if let Some(bound) = self.schema.get() {
            return compare(bound.fingerprint(), &requested);
        }
        match self.schema.set(resolved) {
            Ok(()) => Ok(()),
            Err(_) => compare(
                self.schema
                    .get()
                    .expect("a failed OnceLock set has a winning value")
                    .fingerprint(),
                &requested,
            ),
        }
    }

    pub fn resolved_schema(&self) -> Result<&ResolvedAdapterSchema, AuthError> {
        self.schema.get().ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "MSSQL adapter schema is not bound to an AuthService".into(),
            )
        })
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
