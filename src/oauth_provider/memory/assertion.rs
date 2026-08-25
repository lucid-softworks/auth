use super::MemoryOAuthProviderStore;
use crate::{AuthError, oauth_provider::*};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl OAuthProviderAssertionStore for MemoryOAuthProviderStore {
    async fn reserve_oauth_client_assertion(
        &self,
        assertion: OAuthProviderClientAssertion,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.write().await;
        if state.client_assertions.contains_key(&assertion.id) {
            return Ok(false);
        }
        state
            .client_assertions
            .insert(assertion.id.clone(), assertion);
        Ok(true)
    }

    async fn delete_expired_oauth_client_assertions(
        &self,
        now: DateTime<Utc>,
    ) -> Result<u64, AuthError> {
        let mut state = self.state.write().await;
        let before = state.client_assertions.len();
        state
            .client_assertions
            .retain(|_, assertion| assertion.expires_at > now);
        Ok((before - state.client_assertions.len()) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[tokio::test]
    async fn client_assertions_are_reserved_once_atomically() {
        let store = MemoryOAuthProviderStore::new();
        let assertion = OAuthProviderClientAssertion {
            id: "assertion-digest".into(),
            expires_at: Utc::now() + Duration::minutes(5),
        };
        let (left, right) = tokio::join!(
            store.reserve_oauth_client_assertion(assertion.clone()),
            store.reserve_oauth_client_assertion(assertion),
        );
        assert_eq!(usize::from(left.unwrap()) + usize::from(right.unwrap()), 1);
    }
}
