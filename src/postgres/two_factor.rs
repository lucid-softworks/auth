use super::{PostgresStore, storage_error};
use crate::{AuthError, TwoFactorRecord, TwoFactorStore};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(FromRow)]
struct TwoFactorRow {
    id: Uuid,
    user_id: Uuid,
    enabled: bool,
    encrypted_secret: Option<String>,
    encrypted_backup_codes: Option<String>,
    verified: bool,
    failed_verification_count: i32,
    locked_until: Option<DateTime<Utc>>,
    last_totp_counter: Option<i64>,
}

impl From<TwoFactorRow> for TwoFactorRecord {
    fn from(row: TwoFactorRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            enabled: row.enabled,
            encrypted_secret: row.encrypted_secret,
            encrypted_backup_codes: row.encrypted_backup_codes,
            verified: row.verified,
            failed_verification_count: row.failed_verification_count.max(0) as u32,
            locked_until: row.locked_until,
            last_totp_counter: row.last_totp_counter,
        }
    }
}

const COLUMNS: &str = "id, user_id, enabled, encrypted_secret, encrypted_backup_codes, verified, \
    failed_verification_count, locked_until, last_totp_counter";

#[async_trait]
impl TwoFactorStore for PostgresStore {
    async fn find_two_factor(&self, user_id: Uuid) -> Result<Option<TwoFactorRecord>, AuthError> {
        sqlx::query_as::<_, TwoFactorRow>(&format!(
            "SELECT {COLUMNS} FROM lucid_auth_two_factors WHERE user_id = $1"
        ))
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }

    async fn upsert_two_factor(
        &self,
        record: TwoFactorRecord,
    ) -> Result<TwoFactorRecord, AuthError> {
        sqlx::query_as::<_, TwoFactorRow>(&format!(
            "INSERT INTO lucid_auth_two_factors ({COLUMNS}) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
             ON CONFLICT (user_id) DO UPDATE SET \
               enabled = EXCLUDED.enabled, encrypted_secret = EXCLUDED.encrypted_secret, \
               encrypted_backup_codes = EXCLUDED.encrypted_backup_codes, \
               verified = EXCLUDED.verified, \
               failed_verification_count = EXCLUDED.failed_verification_count, \
               locked_until = EXCLUDED.locked_until, \
               last_totp_counter = EXCLUDED.last_totp_counter \
             RETURNING {COLUMNS}"
        ))
        .bind(record.id)
        .bind(record.user_id)
        .bind(record.enabled)
        .bind(record.encrypted_secret)
        .bind(record.encrypted_backup_codes)
        .bind(record.verified)
        .bind(
            i32::try_from(record.failed_verification_count).map_err(|_| {
                AuthError::InvalidRequest("two-factor failure count is too large".into())
            })?,
        )
        .bind(record.locked_until)
        .bind(record.last_totp_counter)
        .fetch_one(&self.pool)
        .await
        .map(Into::into)
        .map_err(storage_error)
    }

    async fn delete_two_factor(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM lucid_auth_two_factors WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }

    async fn replace_backup_codes(
        &self,
        user_id: Uuid,
        expected: &str,
        replacement: String,
    ) -> Result<bool, AuthError> {
        sqlx::query(
            "UPDATE lucid_auth_two_factors SET encrypted_backup_codes = $1 \
             WHERE user_id = $2 AND encrypted_backup_codes = $3",
        )
        .bind(replacement)
        .bind(user_id)
        .bind(expected)
        .execute(&self.pool)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(storage_error)
    }

    async fn accept_totp_counter(
        &self,
        user_id: Uuid,
        counter: i64,
        enable: bool,
    ) -> Result<bool, AuthError> {
        sqlx::query(
            "UPDATE lucid_auth_two_factors SET \
               last_totp_counter = $1, \
               enabled = CASE WHEN $2 THEN TRUE ELSE enabled END, \
               verified = CASE WHEN $2 THEN TRUE ELSE verified END \
             WHERE user_id = $3 AND \
               (last_totp_counter IS NULL OR last_totp_counter < $1)",
        )
        .bind(counter)
        .bind(enable)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(storage_error)
    }

    async fn record_two_factor_failure(
        &self,
        user_id: Uuid,
        max_attempts: u32,
        locked_until: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let max_attempts = i32::try_from(max_attempts).map_err(|_| {
            AuthError::InvalidConfiguration("two-factor attempt budget is too large".into())
        })?;
        sqlx::query_scalar::<_, bool>(
            "UPDATE lucid_auth_two_factors SET \
               failed_verification_count = failed_verification_count + 1, \
               locked_until = CASE \
                 WHEN failed_verification_count + 1 >= $2 THEN $3 ELSE locked_until END \
             WHERE user_id = $1 \
             RETURNING failed_verification_count >= $2",
        )
        .bind(user_id)
        .bind(max_attempts)
        .bind(locked_until)
        .fetch_optional(&self.pool)
        .await
        .map(|locked| locked.unwrap_or(false))
        .map_err(storage_error)
    }

    async fn reset_two_factor_failures(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE lucid_auth_two_factors SET failed_verification_count = 0, locked_until = NULL \
             WHERE user_id = $1",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
    }
}
