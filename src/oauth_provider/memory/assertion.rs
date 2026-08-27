use super::{MemoryOAuthProviderStore, create_id};
use crate::{AuthError, DatabaseIdSupplier, oauth_provider::*};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl OAuthProviderAssertionStore for MemoryOAuthProviderStore {
    async fn reserve_oauth_client_assertion(
        &self,
        id: &dyn DatabaseIdSupplier,
        mut assertion: OAuthProviderClientAssertion,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.write().await;
        if state.client_assertions.contains_key(&assertion.jti) {
            return Ok(false);
        }
        assertion.id = create_id(&mut state, "oauthClientAssertion", id)?;
        state
            .client_assertions
            .insert(assertion.jti.clone(), assertion);
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn client_assertions_are_reserved_once_atomically() {
        let store = MemoryOAuthProviderStore::new();
        let assertion = OAuthProviderClientAssertion {
            id: String::new(),
            jti: "assertion-digest".into(),
            expires_at: Utc::now() + Duration::minutes(5),
        };
        let calls = AtomicUsize::new(0);
        let id = || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(crate::PreparedDatabaseId::Value(
                crate::DatabaseIdValue::String(uuid::Uuid::new_v4().to_string()),
            ))
        };
        let (left, right) = tokio::join!(
            store.reserve_oauth_client_assertion(&id, assertion.clone()),
            store.reserve_oauth_client_assertion(&id, assertion),
        );
        assert_eq!(usize::from(left.unwrap()) + usize::from(right.unwrap()), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
