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

#[cfg(test)]
mod test_support;

use crate::postgres::{PostgresModel, PostgresStore};
use sqlx::PgPool;

/// PostgreSQL persistence for one remapped Agent Auth plugin schema.
#[derive(Clone)]
pub struct PostgresAgentAuthStore {
    store: PostgresStore,
}

impl PostgresAgentAuthStore {
    pub fn new(store: PostgresStore) -> Self {
        Self { store }
    }

    fn pool(&self) -> &PgPool {
        self.store.pool()
    }

    fn model(&self, logical: &str) -> Result<PostgresModel<'_>, crate::AuthError> {
        self.store.physical_model(logical)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_auth::AgentAuthStore;
    use sqlx::postgres::PgPoolOptions;

    #[tokio::test]
    async fn operations_fail_cleanly_without_the_agent_auth_plugin_schema() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/lucid_auth")
            .unwrap();
        let store = PostgresAgentAuthStore::new(PostgresStore::new(
            pool,
            crate::postgres::PostgresAdapterConfig::default(),
        ));
        let error = store.find_agent("agent-1").await.unwrap_err();
        assert!(matches!(error, crate::AuthError::InvalidConfiguration(_)));
    }
}
