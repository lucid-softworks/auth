use super::{PostgresStore, storage_error};
use crate::{AuthError, VerificationStore, VerificationValue};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[derive(sqlx::FromRow)]
struct VerificationRow {
    purpose: String,
    identifier: String,
    payload: serde_json::Value,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

impl From<VerificationRow> for VerificationValue {
    fn from(row: VerificationRow) -> Self {
        Self {
            purpose: row.purpose,
            identifier: row.identifier,
            payload: row.payload,
            expires_at: row.expires_at,
            created_at: row.created_at,
        }
    }
}

#[async_trait]
impl VerificationStore for PostgresStore {
    async fn create_verification(&self, value: VerificationValue) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO lucid_auth_verifications \
             (purpose, identifier, payload, expires_at, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(value.purpose)
        .bind(value.identifier)
        .bind(value.payload)
        .bind(value.expires_at)
        .bind(value.created_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
    }

    async fn consume_verification(
        &self,
        purpose: &str,
        identifier: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<VerificationValue>, AuthError> {
        sqlx::query_as::<_, VerificationRow>(
            "DELETE FROM lucid_auth_verifications \
             WHERE purpose = $1 AND identifier = $2 \
             RETURNING purpose, identifier, payload, expires_at, created_at",
        )
        .bind(purpose)
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await
        .map(|row| {
            row.map(VerificationValue::from)
                .filter(|value| value.expires_at > now)
        })
        .map_err(storage_error)
    }

    async fn delete_expired_verifications(&self, now: DateTime<Utc>) -> Result<u64, AuthError> {
        sqlx::query("DELETE FROM lucid_auth_verifications WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map(|result| result.rows_affected())
            .map_err(storage_error)
    }
}
