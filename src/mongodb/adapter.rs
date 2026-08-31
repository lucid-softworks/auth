use crate::{
    AdapterSchemaOptions, AuthError, AuthSchemaCatalog, DatabaseIdGenerationRequest,
    DatabaseIdGenerationResult, DatabaseIdGenerator, ResolvedAdapterSchema, SchemaFingerprint,
};
use mongodb::{Client, Database};
use std::{collections::HashSet, sync::{Arc, OnceLock}};

/// Better Auth MongoDB adapter options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MongoAdapterConfig {
    pub debug_logs: bool,
    pub use_plural: bool,
    /// `None` enables transactions when a client is supplied, matching Better Auth.
    pub transaction: Option<bool>,
}

#[derive(Debug)]
struct MongoIdGenerator;

impl DatabaseIdGenerator for MongoIdGenerator {
    fn generate(&self, _request: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
        DatabaseIdGenerationResult::Id(mongodb::bson::oid::ObjectId::new().to_hex())
    }
}

static ID_GENERATOR: MongoIdGenerator = MongoIdGenerator;

/// In-process backend using the official MongoDB Rust driver.
#[derive(Clone)]
pub struct MongoStore {
    pub(super) database: Database,
    pub(super) client: Option<Client>,
    adapter_config: MongoAdapterConfig,
    schema: Arc<OnceLock<BoundMongoSchema>>,
    pub(super) index_setup: Arc<tokio::sync::Mutex<HashSet<String>>>,
}

struct BoundMongoSchema {
    resolved: ResolvedAdapterSchema,
    physical: super::schema::MongoSchema,
}

impl MongoStore {
    /// Uses a selected caller-owned database and optional client.
    pub fn new(
        database: Database,
        client: Option<Client>,
        adapter_config: MongoAdapterConfig,
    ) -> Self {
        Self {
            database,
            client,
            adapter_config,
            schema: Arc::new(OnceLock::new()),
            index_setup: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        }
    }

    /// Connects with the official driver's defaults and retains the client for transactions.
    pub async fn connect(
        uri: &str,
        database_name: &str,
        adapter_config: MongoAdapterConfig,
    ) -> Result<Self, AuthError> {
        let client = Client::with_uri_str(uri).await.map_err(storage)?;
        let database = client.database(database_name);
        Ok(Self::new(database, Some(client), adapter_config))
    }

    pub fn database(&self) -> &Database {
        &self.database
    }

    pub fn client(&self) -> Option<&Client> {
        self.client.as_ref()
    }

    pub fn transactions_enabled(&self) -> bool {
        self.client.is_some() && self.adapter_config.transaction.unwrap_or(true)
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
        let bound = BoundMongoSchema {
            physical: super::schema::MongoSchema::new(&resolved)?,
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

    pub(super) fn physical_schema(&self) -> Result<&super::schema::MongoSchema, AuthError> {
        self.bound_schema().map(|schema| &schema.physical)
    }

    pub(super) fn id_generator(&self) -> &'static dyn DatabaseIdGenerator {
        &ID_GENERATOR
    }

    fn bound_schema(&self) -> Result<&BoundMongoSchema, AuthError> {
        self.schema.get().ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "MongoDB adapter schema is not bound to an AuthService".into(),
            )
        })
    }
}

fn compare(bound: &SchemaFingerprint, requested: &SchemaFingerprint) -> Result<(), AuthError> {
    if bound == requested {
        Ok(())
    } else {
        Err(AuthError::InvalidConfiguration(
            "MongoDB adapter is already bound to a different Better Auth schema".into(),
        ))
    }
}

fn storage(error: mongodb::error::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
