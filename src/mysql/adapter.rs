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
    pool: MySqlPool,
    adapter_config: MySqlAdapterConfig,
    schema: Arc<OnceLock<ResolvedAdapterSchema>>,
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

    /// Returns the bound shared schema descriptor.
    pub fn resolved_schema(&self) -> Result<&ResolvedAdapterSchema, AuthError> {
        self.schema.get().ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "MySQL adapter schema is not bound to an AuthService".into(),
            )
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
