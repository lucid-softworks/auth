use super::{MemoryStore, RateLimitWindow};
use crate::{AuthError, SecurityStore};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use uuid::Uuid;

#[async_trait]
impl SecurityStore for MemoryStore {
    async fn rate_limit_exceeded(
        &self,
        key: &str,
        now: DateTime<Utc>,
        max_attempts: usize,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.write().await;
        state.rate_limits.retain(|_, limit| limit.expires_at > now);
        Ok(state
            .rate_limits
            .get(key)
            .is_some_and(|limit| limit.attempts >= max_attempts))
    }

    async fn record_auth_failure(
        &self,
        key: &str,
        now: DateTime<Utc>,
        window: chrono::Duration,
    ) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        let limit = state
            .rate_limits
            .entry(key.to_owned())
            .or_insert(RateLimitWindow {
                attempts: 0,
                expires_at: now + window,
            });
        if limit.expires_at <= now {
            limit.attempts = 0;
            limit.expires_at = now + window;
        }
        limit.attempts += 1;
        Ok(())
    }

    async fn clear_auth_failures(&self, key: &str) -> Result<(), AuthError> {
        self.state.write().await.rate_limits.remove(key);
        Ok(())
    }

    async fn replace_recovery_codes(
        &self,
        user_id: Uuid,
        code_hashes: Vec<String>,
    ) -> Result<(), AuthError> {
        self.state
            .write()
            .await
            .recovery_codes
            .insert(user_id, code_hashes.into_iter().collect());
        Ok(())
    }

    async fn consume_recovery_code(
        &self,
        user_id: Uuid,
        code_hash: &str,
    ) -> Result<bool, AuthError> {
        Ok(self
            .state
            .write()
            .await
            .recovery_codes
            .get_mut(&user_id)
            .is_some_and(|codes| codes.remove(code_hash)))
    }

    async fn recovery_code_count(&self, user_id: Uuid) -> Result<usize, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .recovery_codes
            .get(&user_id)
            .map_or(0, HashSet::len))
    }

    async fn delete_recovery_codes(&self, user_id: Uuid) -> Result<(), AuthError> {
        self.state.write().await.recovery_codes.remove(&user_id);
        Ok(())
    }
}
