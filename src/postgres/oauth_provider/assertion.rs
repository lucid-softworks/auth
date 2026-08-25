use super::{super::storage_error, PostgresOAuthProviderStore};
use crate::{
    AuthError,
    oauth_provider::{
        OAuthProviderAssertionStore, OAuthProviderClientAssertion, schema::OAuthProviderModel,
    },
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl OAuthProviderAssertionStore for PostgresOAuthProviderStore {
    async fn reserve_oauth_client_assertion(
        &self,
        assertion: OAuthProviderClientAssertion,
    ) -> Result<bool, AuthError> {
        let model = self.schema.model(OAuthProviderModel::ClientAssertion);
        sqlx::query(&format!(
            "INSERT INTO {} (\"id\", {}) VALUES ($1,$2) ON CONFLICT (\"id\") DO NOTHING",
            model.table(),
            model.column("expiresAt")
        ))
        .bind(assertion.id)
        .bind(assertion.expires_at)
        .execute(self.pool())
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(storage_error)
    }

    async fn delete_expired_oauth_client_assertions(
        &self,
        now: DateTime<Utc>,
    ) -> Result<u64, AuthError> {
        let model = self.schema.model(OAuthProviderModel::ClientAssertion);
        sqlx::query(&format!(
            "DELETE FROM {} WHERE {} <= $1",
            model.table(),
            model.column("expiresAt")
        ))
        .bind(now)
        .execute(self.pool())
        .await
        .map(|result| result.rows_affected())
        .map_err(storage_error)
    }
}
