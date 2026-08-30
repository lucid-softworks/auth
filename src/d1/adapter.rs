use super::{
    D1Database, D1Filter, D1FindOptions, D1MigrationError, D1MigrationMode, D1MigrationPlan,
    query::execute, schema::D1Schema, transport::SharedD1Database,
};
use crate::{
    AdapterSchemaOptions, AuthError, AuthSchemaCatalog, ResolvedAdapterSchema, SchemaFingerprint,
};
use serde_json::{Map, Value};
use std::sync::{Arc, OnceLock};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct D1AdapterConfig {
    /// Apply Better Auth's literal `s` suffix to physical table names.
    pub use_plural: bool,
}

/// Native, non-transactional Cloudflare D1 adapter.
#[derive(Clone)]
pub struct D1Store {
    pub(super) database: SharedD1Database,
    adapter_config: D1AdapterConfig,
    schema: Arc<OnceLock<Arc<BoundD1Schema>>>,
}

pub(super) struct BoundD1Schema {
    pub resolved: ResolvedAdapterSchema,
    pub physical: D1Schema,
}

impl D1Store {
    pub fn new(database: Arc<dyn D1Database>, adapter_config: D1AdapterConfig) -> Self {
        Self {
            database,
            adapter_config,
            schema: Arc::new(OnceLock::new()),
        }
    }

    pub fn database(&self) -> &dyn D1Database {
        self.database.as_ref()
    }

    /// D1 never exposes Better Auth's interactive transaction capability.
    pub const fn supports_transactions(&self) -> bool {
        false
    }

    /// D1 rejects streaming instead of buffering and pretending to stream.
    pub fn stream_records(&self) -> Result<(), AuthError> {
        Err(AuthError::Storage(
            "D1 does not support streaming queries.".into(),
        ))
    }

    /// D1 rejects begin/commit/rollback instead of emulating a transaction.
    pub fn begin_transaction(&self) -> Result<(), AuthError> {
        Err(AuthError::Storage(
            "D1 does not support interactive transactions. Use atomic adapter operations instead."
                .into(),
        ))
    }

    pub fn bind_schema(&self, schema: Arc<AuthSchemaCatalog>) -> Result<(), AuthError> {
        self.bind_catalog(schema)
    }

    pub async fn insert_record(
        &self,
        model: &str,
        record: Map<String, Value>,
    ) -> Result<Map<String, Value>, AuthError> {
        execute::insert(self.database(), self.physical_schema()?, model, record).await
    }

    pub async fn find_record(
        &self,
        model: &str,
        filters: &[D1Filter],
        select: &[String],
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::find_one(
            self.database(),
            self.physical_schema()?,
            model,
            filters,
            select,
        )
        .await
    }

    pub async fn find_records(
        &self,
        model: &str,
        filters: &[D1Filter],
        options: &D1FindOptions,
    ) -> Result<Vec<Map<String, Value>>, AuthError> {
        execute::find_many(
            self.database(),
            self.physical_schema()?,
            model,
            filters,
            options,
        )
        .await
    }

    pub async fn update_record(
        &self,
        model: &str,
        filters: &[D1Filter],
        values: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::update_one(
            self.database(),
            self.physical_schema()?,
            model,
            filters,
            values,
        )
        .await
    }

    pub async fn update_records(
        &self,
        model: &str,
        filters: &[D1Filter],
        values: Map<String, Value>,
    ) -> Result<u64, AuthError> {
        execute::update_many(
            self.database(),
            self.physical_schema()?,
            model,
            filters,
            values,
        )
        .await
    }

    pub async fn count_records(&self, model: &str, filters: &[D1Filter]) -> Result<u64, AuthError> {
        execute::count(self.database(), self.physical_schema()?, model, filters).await
    }

    pub async fn delete_records(
        &self,
        model: &str,
        filters: &[D1Filter],
    ) -> Result<u64, AuthError> {
        execute::delete_many(self.database(), self.physical_schema()?, model, filters).await
    }

    /// Atomically selects at most one matching ID and deletes it with RETURNING.
    pub async fn consume_record(
        &self,
        model: &str,
        filters: &[D1Filter],
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::consume_one(self.database(), self.physical_schema()?, model, filters).await
    }

    /// Atomically applies in-database increments and field updates to one row.
    pub async fn increment_record(
        &self,
        model: &str,
        filters: &[D1Filter],
        increments: Map<String, Value>,
        set: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        execute::increment_one(
            self.database(),
            self.physical_schema()?,
            model,
            filters,
            increments,
            set,
        )
        .await
    }

    pub async fn migration_plan(
        &self,
        schema: Arc<AuthSchemaCatalog>,
        mode: D1MigrationMode,
    ) -> Result<D1MigrationPlan, D1MigrationError> {
        self.bind_catalog(schema)
            .map_err(|error| D1MigrationError::Configuration(error.to_string()))?;
        let bound = self
            .bound_schema()
            .map_err(|error| D1MigrationError::Configuration(error.to_string()))?;
        super::migration::plan(self.database(), &bound.resolved, &bound.physical, mode).await
    }

    pub async fn migrate(
        &self,
        schema: Arc<AuthSchemaCatalog>,
    ) -> Result<D1MigrationPlan, D1MigrationError> {
        let plan = self
            .migration_plan(schema, D1MigrationMode::Execute)
            .await?;
        plan.run(self.database()).await?;
        Ok(plan)
    }

    pub(super) fn physical_schema(&self) -> Result<&D1Schema, AuthError> {
        self.bound_schema().map(|schema| &schema.physical)
    }

    fn bound_schema(&self) -> Result<&BoundD1Schema, AuthError> {
        self.schema.get().map(Arc::as_ref).ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "D1 adapter schema is not bound to an AuthService".into(),
            )
        })
    }

    fn bind_catalog(&self, schema: Arc<AuthSchemaCatalog>) -> Result<(), AuthError> {
        let resolved = ResolvedAdapterSchema::new(
            schema,
            AdapterSchemaOptions {
                use_plural: self.adapter_config.use_plural,
            },
        )
        .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?;
        let requested = resolved.fingerprint().clone();
        let bound = Arc::new(BoundD1Schema {
            physical: D1Schema::new(&resolved)?,
            resolved,
        });
        if let Some(existing) = self.schema.get() {
            return compare(existing.resolved.fingerprint(), &requested);
        }
        match self.schema.set(bound) {
            Ok(()) => Ok(()),
            Err(_) => compare(
                self.schema
                    .get()
                    .expect("failed OnceLock set has a winner")
                    .resolved
                    .fingerprint(),
                &requested,
            ),
        }
    }
}

fn compare(bound: &SchemaFingerprint, requested: &SchemaFingerprint) -> Result<(), AuthError> {
    if bound == requested {
        Ok(())
    } else {
        Err(AuthError::InvalidConfiguration(
            "D1 adapter is already bound to a different Better Auth schema".into(),
        ))
    }
}
