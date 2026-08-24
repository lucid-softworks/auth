use super::{MemoryStore, RateLimitWindow};
use crate::{
    AuthError, RateLimitOutcome, RateLimitRule, SecurityStore,
    rate_limit::{duration, retry_after},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl SecurityStore for MemoryStore {
    async fn consume_rate_limit(
        &self,
        key: &str,
        now: DateTime<Utc>,
        rule: RateLimitRule,
        longest_window: u64,
    ) -> Result<RateLimitOutcome, AuthError> {
        let window = duration(rule.window)?;
        let prune_window = duration(longest_window)?;
        let mut state = self.state.write().await;
        state
            .rate_limits
            .retain(|_, limit| now - limit.last_request < prune_window);
        let Some(limit) = state.rate_limits.get_mut(key) else {
            state.rate_limits.insert(
                key.to_owned(),
                RateLimitWindow {
                    count: 1,
                    last_request: now,
                },
            );
            return Ok(RateLimitOutcome::allowed());
        };
        if now - limit.last_request >= window {
            limit.count = 1;
            limit.last_request = now;
            return Ok(RateLimitOutcome::allowed());
        }
        if limit.count >= rule.max {
            return Ok(RateLimitOutcome::denied(retry_after(
                limit.last_request,
                window,
                now,
            )));
        }
        limit.count += 1;
        limit.last_request = now;
        Ok(RateLimitOutcome::allowed())
    }
}
