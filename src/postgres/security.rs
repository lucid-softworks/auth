use super::{PostgresStore, storage_error};
use crate::{AuthError, SecurityStore};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl SecurityStore for PostgresStore {
    async fn rate_limit_exceeded(
        &self,
        key: &str,
        now: DateTime<Utc>,
        max_attempts: usize,
    ) -> Result<bool, AuthError> {
        sqlx::query("DELETE FROM lucid_auth_rate_limits WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        sqlx::query_scalar::<_, bool>(
            "SELECT COALESCE((SELECT attempts >= $2 FROM lucid_auth_rate_limits WHERE key = $1), FALSE)",
        )
        .bind(key)
        .bind(i32::try_from(max_attempts).unwrap_or(i32::MAX))
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)
    }

    async fn record_auth_failure(
        &self,
        key: &str,
        now: DateTime<Utc>,
        window: chrono::Duration,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO lucid_auth_rate_limits (key, attempts, expires_at) VALUES ($1, 1, $2) \
             ON CONFLICT (key) DO UPDATE SET \
               attempts = CASE WHEN lucid_auth_rate_limits.expires_at <= $3 THEN 1 \
                               ELSE lucid_auth_rate_limits.attempts + 1 END, \
               expires_at = CASE WHEN lucid_auth_rate_limits.expires_at <= $3 THEN $2 \
                                 ELSE lucid_auth_rate_limits.expires_at END",
        )
        .bind(key)
        .bind(now + window)
        .bind(now)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
    }

    async fn clear_auth_failures(&self, key: &str) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM lucid_auth_rate_limits WHERE key = $1")
            .bind(key)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }
}
