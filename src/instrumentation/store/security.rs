use super::InstrumentedAuthStore;
use crate::{
    AuthError, RateLimitOutcome, RateLimitRule, SecurityStore,
    instrumentation::{AdapterOperation, with_adapter_operation},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl SecurityStore for InstrumentedAuthStore {
    async fn consume_rate_limit(
        &self,
        id: &dyn crate::DatabaseIdSupplier,
        key: &str,
        now: DateTime<Utc>,
        rule: RateLimitRule,
        longest_window: u64,
    ) -> Result<RateLimitOutcome, AuthError> {
        with_adapter_operation(
            AdapterOperation::IncrementOne,
            "rateLimit",
            self.inner
                .consume_rate_limit(id, key, now, rule, longest_window),
        )
        .await
    }
}
