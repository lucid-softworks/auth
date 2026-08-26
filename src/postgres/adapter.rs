use crate::{
    AdapterSchemaOptions, AuthError, AuthSchemaCatalog, ResolvedAdapterSchema, SchemaFingerprint,
};
use sqlx::PgPool;
use std::sync::{Arc, OnceLock};

/// Better Auth PostgreSQL adapter schema options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PostgresAdapterConfig {
    pub use_plural: bool,
}

/// PostgreSQL/SQLx persistence adapter.
#[derive(Clone)]
pub struct PostgresStore {
    pub(super) pool: PgPool,
    adapter_config: PostgresAdapterConfig,
    schema: Arc<OnceLock<Arc<BoundPostgresSchema>>>,
}

struct BoundPostgresSchema {
    resolved: ResolvedAdapterSchema,
    physical: super::physical_schema::PostgresPhysicalSchema,
}

impl PostgresStore {
    pub fn new(pool: PgPool, adapter_config: PostgresAdapterConfig) -> Self {
        Self {
            pool,
            adapter_config,
            schema: Arc::new(OnceLock::new()),
        }
    }

    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub(crate) fn resolved_schema(&self) -> Result<&ResolvedAdapterSchema, AuthError> {
        self.bound_schema().map(|schema| &schema.resolved)
    }

    pub(super) fn physical_schema(
        &self,
    ) -> Result<&super::physical_schema::PostgresPhysicalSchema, AuthError> {
        self.bound_schema().map(|schema| &schema.physical)
    }

    pub(crate) fn physical_model(
        &self,
        logical: &str,
    ) -> Result<super::PostgresModel<'_>, AuthError> {
        self.physical_schema()?.model(logical)
    }

    pub(crate) fn physical_model_if_present(
        &self,
        logical: &str,
    ) -> Result<Option<super::PostgresModel<'_>>, AuthError> {
        Ok(self.physical_schema()?.model_if_present(logical))
    }

    fn bound_schema(&self) -> Result<&BoundPostgresSchema, AuthError> {
        self.schema.get().map(Arc::as_ref).ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "PostgreSQL adapter schema is not bound to an AuthService".into(),
            )
        })
    }

    pub(super) fn bind_catalog(&self, schema: Arc<AuthSchemaCatalog>) -> Result<(), AuthError> {
        let resolved = ResolvedAdapterSchema::new(
            schema,
            AdapterSchemaOptions {
                use_plural: self.adapter_config.use_plural,
            },
        )
        .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?;
        let requested_fingerprint = resolved.fingerprint().clone();
        let resolved = Arc::new(BoundPostgresSchema {
            physical: super::physical_schema::PostgresPhysicalSchema::new(&resolved)?,
            resolved,
        });
        if let Some(bound) = self.schema.get() {
            return compare(bound.resolved.fingerprint(), &requested_fingerprint);
        }
        match self.schema.set(resolved.clone()) {
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
}

fn compare(bound: &SchemaFingerprint, requested: &SchemaFingerprint) -> Result<(), AuthError> {
    if bound == requested {
        Ok(())
    } else {
        Err(AuthError::InvalidConfiguration(
            "PostgreSQL adapter is already bound to a different Better Auth schema".into(),
        ))
    }
}
