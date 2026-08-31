use super::{eq, record};
use crate::{
    AuthError, DatabaseIdSupplier, OAuthProviderAssertionStore, OAuthProviderClientAssertion,
    mysql::{MySqlFilterOperator, MySqlStore},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl OAuthProviderAssertionStore for MySqlStore {
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
        match self.insert_required_record("oauthClientAssertion", values).await {
            Ok(_) => Ok(true),
            Err(error) if crate::mysql::error::is_unique_violation(&error) => {
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
        filter.operator = MySqlFilterOperator::Lt;
        self.delete_records("oauthClientAssertion", &[filter]).await
    }
}
