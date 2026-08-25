mod agent;
mod agent_lifecycle;
mod approval;
mod enrollment;
mod grant;
mod host;
mod host_lifecycle;
mod query;
mod rows;
mod store;
mod transition;
mod transition_write;

use crate::agent_auth::{AgentAuthSchema, AgentAuthSchemaError, schema::ResolvedAgentAuthSchema};
use sqlx::PgPool;

/// PostgreSQL persistence for one remapped Agent Auth plugin schema.
#[derive(Clone)]
pub struct PostgresAgentAuthStore {
    pool: PgPool,
    schema: ResolvedAgentAuthSchema,
    migration_sql: String,
}

impl PostgresAgentAuthStore {
    pub fn new(pool: PgPool, schema: &AgentAuthSchema) -> Result<Self, AgentAuthSchemaError> {
        let schema = ResolvedAgentAuthSchema::new(schema)?;
        let migration_sql = schema.migration_sql();
        Ok(Self {
            pool,
            schema,
            migration_sql,
        })
    }

    /// SQL that creates the four remapped Agent Auth models and their indexes.
    pub fn migration_sql(&self) -> &str {
        &self.migration_sql
    }

    fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn storage_error(error: impl std::fmt::Display) -> crate::AuthError {
    crate::AuthError::Storage(error.to_string())
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
}

async fn lock_creation(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    model: &str,
) -> Result<(), crate::AuthError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(model)
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
    Ok(())
}
