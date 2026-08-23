use super::{PostgresStore, UserRow, storage_error};
use crate::{AuthError, AuthUser, EmailVerificationOutcome, VerificationStore, VerificationValue};
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

pub(super) async fn consume_email_verification(
    pool: &sqlx::PgPool,
    token_hash: &str,
    now: DateTime<Utc>,
) -> Result<EmailVerificationOutcome, AuthError> {
    let mut transaction = pool.begin().await.map_err(storage_error)?;
    let value = sqlx::query_as::<_, VerificationRow>(
        "DELETE FROM lucid_auth_verifications \
         WHERE purpose = 'email-verification' AND identifier = $1 \
         RETURNING purpose, identifier, payload, expires_at, created_at",
    )
    .bind(token_hash)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(storage_error)?;
    let Some(value) = value else {
        transaction.commit().await.map_err(storage_error)?;
        return Ok(EmailVerificationOutcome::InvalidToken);
    };
    if value.expires_at <= now {
        transaction.commit().await.map_err(storage_error)?;
        return Ok(EmailVerificationOutcome::Expired);
    }
    let email = value
        .payload
        .get("email")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AuthError::Storage("email verification payload is invalid".into()))?;
    let user = sqlx::query_as::<_, UserRow>(
        "SELECT id, username, display_username, name, email, email_verified, image, role, \
         is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at \
         FROM lucid_auth_users WHERE LOWER(email) = LOWER($1) FOR UPDATE",
    )
    .bind(email)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(storage_error)?
    .map(AuthUser::from);
    let Some(user) = user else {
        transaction.commit().await.map_err(storage_error)?;
        return Ok(EmailVerificationOutcome::UserNotFound);
    };
    if user.email_verified {
        transaction.commit().await.map_err(storage_error)?;
        return Ok(EmailVerificationOutcome::AlreadyVerified(user));
    }
    let user = sqlx::query_as::<_, UserRow>(
        "UPDATE lucid_auth_users SET email_verified = TRUE, updated_at = $2 WHERE id = $1 \
         RETURNING id, username, display_username, name, email, email_verified, image, role, \
           is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at",
    )
    .bind(user.id)
    .bind(now)
    .fetch_one(&mut *transaction)
    .await
    .map(AuthUser::from)
    .map_err(storage_error)?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(EmailVerificationOutcome::Verified(user))
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
