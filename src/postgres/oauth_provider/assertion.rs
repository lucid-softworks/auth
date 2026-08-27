use super::{
    super::{rows::insert_query_prefix, storage_error},
    PostgresOAuthProviderStore, rows,
};
use crate::{
    AuthError, DatabaseIdSupplier,
    oauth_provider::{OAuthProviderAssertionStore, OAuthProviderClientAssertion},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl OAuthProviderAssertionStore for PostgresOAuthProviderStore {
    async fn reserve_oauth_client_assertion(
        &self,
        id: &dyn DatabaseIdSupplier,
        assertion: OAuthProviderClientAssertion,
    ) -> Result<bool, AuthError> {
        let model = self.model("oauthClientAssertion")?;
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&assertion.jti)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let mut existing = sqlx::QueryBuilder::new("SELECT 1 FROM ");
        existing
            .push(model.quoted_table())
            .push(" WHERE ")
            .push(model.quoted_column("jti")?)
            .push(" = ")
            .push_bind(assertion.jti.clone());
        if existing
            .build_query_scalar::<i32>()
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?
            .is_some()
        {
            return Ok(false);
        }
        let prepared_id = id.prepare()?;
        let writes = rows::insert_writes(&model, &assertion, &prepared_id, [])?;
        let mut query = insert_query_prefix(&model, writes);
        query
            .push(" ON CONFLICT (")
            .push(model.quoted_column("jti")?)
            .push(") DO NOTHING");
        let reserved = query
            .build()
            .execute(&mut *transaction)
            .await
            .map(|result| result.rows_affected() == 1)
            .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(reserved)
    }

    async fn delete_expired_oauth_client_assertions(
        &self,
        now: DateTime<Utc>,
    ) -> Result<u64, AuthError> {
        let model = self.model("oauthClientAssertion")?;
        let mut query = sqlx::QueryBuilder::new("DELETE FROM ");
        query
            .push(model.quoted_table())
            .push(" WHERE ")
            .push(model.quoted_column("expiresAt")?)
            .push(" <= ")
            .push_bind(now);
        query
            .build()
            .execute(self.pool())
            .await
            .map(|result| result.rows_affected())
            .map_err(storage_error)
    }
}
