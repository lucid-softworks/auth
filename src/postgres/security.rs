use super::{PostgresStore, storage_error};
use crate::{
    AuthError, RateLimitOutcome, RateLimitRule, SecurityStore,
    rate_limit::{duration, retry_after},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl SecurityStore for PostgresStore {
    async fn consume_rate_limit(
        &self,
        key: &str,
        now: DateTime<Utc>,
        rule: RateLimitRule,
        longest_window: u64,
    ) -> Result<RateLimitOutcome, AuthError> {
        let window = duration(rule.window)?;
        let now_milliseconds = now.timestamp_millis();
        let prune_milliseconds = i64::try_from(longest_window)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .ok_or_else(|| {
                AuthError::InvalidConfiguration("rate-limit window is too large".into())
            })?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(key)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        sqlx::query("DELETE FROM lucid_auth_rate_limits WHERE last_request < $1")
            .bind(now_milliseconds.saturating_sub(prune_milliseconds))
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let current = sqlx::query_as::<_, (i64, i64)>(
            "SELECT count, last_request FROM lucid_auth_rate_limits WHERE key = $1 FOR UPDATE",
        )
        .bind(key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        let outcome = match current {
            None => {
                sqlx::query(
                    "INSERT INTO lucid_auth_rate_limits (key, count, last_request) VALUES ($1, 1, $2)",
                )
                .bind(key)
                .bind(now_milliseconds)
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
                RateLimitOutcome::allowed()
            }
            Some((count, last_request)) => {
                let last =
                    DateTime::<Utc>::from_timestamp_millis(last_request).ok_or_else(|| {
                        AuthError::Storage("rate-limit last request is invalid".into())
                    })?;
                if now - last >= window {
                    update(&mut transaction, key, 1, now_milliseconds).await?;
                    RateLimitOutcome::allowed()
                } else if u64::try_from(count).unwrap_or(u64::MAX) >= u64::from(rule.max) {
                    RateLimitOutcome::denied(retry_after(last, window, now))
                } else {
                    update(
                        &mut transaction,
                        key,
                        count.saturating_add(1),
                        now_milliseconds,
                    )
                    .await?;
                    RateLimitOutcome::allowed()
                }
            }
        };
        transaction.commit().await.map_err(storage_error)?;
        Ok(outcome)
    }
}

async fn update(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    key: &str,
    count: i64,
    last_request: i64,
) -> Result<(), AuthError> {
    sqlx::query("UPDATE lucid_auth_rate_limits SET count = $2, last_request = $3 WHERE key = $1")
        .bind(key)
        .bind(count)
        .bind(last_request)
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}
