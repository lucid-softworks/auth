use super::{MemoryStore, RateLimitWindow};
use crate::{AuthError, SecurityStore};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

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
}
