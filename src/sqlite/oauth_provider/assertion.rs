use super::{eq, record};
use crate::{
    AuthError, DatabaseIdSupplier, OAuthProviderAssertionStore, OAuthProviderClientAssertion,
    sqlite::{SqliteFilterOperator, SqliteStore},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl OAuthProviderAssertionStore for SqliteStore {
    async fn reserve_oauth_client_assertion(
        &self,
        id: &dyn DatabaseIdSupplier,
        assertion: OAuthProviderClientAssertion,
    ) -> Result<bool, AuthError> {
        let values = record(
            self,
            "oauthClientAssertion",
            &assertion,
            Some(id.prepare()?),
            [],
        )?;
        match self.insert_record("oauthClientAssertion", values).await {
            Ok(_) => Ok(true),
            Err(AuthError::Storage(message)) if message.contains("UNIQUE constraint failed") => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    async fn delete_expired_oauth_client_assertions(
        &self,
        now: DateTime<Utc>,
    ) -> Result<u64, AuthError> {
        let mut filter = eq("expiresAt", now);
        filter.operator = SqliteFilterOperator::Lt;
        self.delete_records("oauthClientAssertion", &[filter]).await
    }
}
