use super::{
    super::{rows::insert_query_prefix, storage_error},
    PostgresOAuthProviderStore, rows,
};
use crate::{
    AuthError,
    oauth_provider::{OAuthProviderAssertionStore, OAuthProviderClientAssertion},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl OAuthProviderAssertionStore for PostgresOAuthProviderStore {
    async fn reserve_oauth_client_assertion(
        &self,
        assertion: OAuthProviderClientAssertion,
    ) -> Result<bool, AuthError> {
        let model = self.model("oauthClientAssertion")?;
        let writes = rows::writes(&model, &assertion, [])?;
        let mut query = insert_query_prefix(&model, writes);
        query.push(" ON CONFLICT (\"id\") DO NOTHING");
        query
            .build()
            .execute(self.pool())
            .await
            .map(|result| result.rows_affected() == 1)
            .map_err(storage_error)
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
