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
        id: &dyn crate::store::DatabaseIdSupplier,
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
            let id = self.create_id("rateLimit", id.prepare()?, state.rate_limits.len())?;
            state.rate_limits.insert(
                key.to_owned(),
                RateLimitWindow {
                    _id: id,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{DatabaseIdValue, PreparedDatabaseId};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn rate_limit_id_supplier_runs_only_for_the_insert_branch() {
        let store = MemoryStore::default();
        let calls = AtomicUsize::new(0);
        let supplier = || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(PreparedDatabaseId::Value(DatabaseIdValue::String(
                "rate-id".into(),
            )))
        };
        let now = Utc::now();
        let rule = RateLimitRule::new(60, 10);
        store
            .consume_rate_limit(&supplier, "same", now, rule, 60)
            .await
            .unwrap();
        store
            .consume_rate_limit(&supplier, "same", now, rule, 60)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}
