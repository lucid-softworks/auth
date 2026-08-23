use super::{PostgresStore, UserRow, storage_error};
use crate::{
    AuthError, AuthUser, EmailVerificationOutcome, PasswordResetOutcome, VerificationStore,
    VerificationValue,
};
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

pub(super) async fn consume_password_reset(
    pool: &sqlx::PgPool,
    token_hash: &str,
    password_hash: String,
    now: DateTime<Utc>,
    revoke_sessions: bool,
) -> Result<PasswordResetOutcome, AuthError> {
    let mut transaction = pool.begin().await.map_err(storage_error)?;
    let value = sqlx::query_as::<_, VerificationRow>(
        "DELETE FROM lucid_auth_verifications \
         WHERE purpose = 'password-reset' AND identifier = $1 \
         RETURNING purpose, identifier, payload, expires_at, created_at",
    )
    .bind(token_hash)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(storage_error)?;
    let Some(value) = value.filter(|value| value.expires_at > now) else {
        transaction.commit().await.map_err(storage_error)?;
        return Ok(PasswordResetOutcome::InvalidToken);
    };
    let user_id = value
        .payload
        .get("user_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .ok_or_else(|| AuthError::Storage("password reset payload is invalid".into()))?;
    let user = super::user::load_by_id_transaction(&mut transaction, user_id).await?;
    let Some(user) = user else {
        transaction.commit().await.map_err(storage_error)?;
        return Ok(PasswordResetOutcome::UserNotFound);
    };
    sqlx::query(
        "INSERT INTO lucid_auth_accounts \
         (id, user_id, provider_id, account_id, password_hash, created_at, updated_at) \
         VALUES ($1, $2, 'credential', $3, $4, $5, $5) \
         ON CONFLICT (user_id, provider_id) DO UPDATE SET \
           password_hash = EXCLUDED.password_hash, updated_at = EXCLUDED.updated_at",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(user.id)
    .bind(user.id.to_string())
    .bind(password_hash)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(storage_error)?;
    let user = sqlx::query_as::<_, UserRow>(
        "UPDATE lucid_auth_users SET must_change_password = FALSE, updated_at = $2 WHERE id = $1 \
         RETURNING id, username, display_username, name, email, email_verified, image, role, \
           is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at",
    )
    .bind(user.id)
    .bind(now)
    .fetch_one(&mut *transaction)
    .await
    .map(AuthUser::from)
    .map_err(storage_error)?;
    if revoke_sessions {
        sqlx::query("DELETE FROM lucid_auth_sessions WHERE user_id = $1")
            .bind(user.id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
    }
    transaction.commit().await.map_err(storage_error)?;
    Ok(PasswordResetOutcome::Reset(Box::new(user)))
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

    async fn find_verification(
        &self,
        purpose: &str,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        sqlx::query_as::<_, VerificationRow>(
            "SELECT purpose, identifier, payload, expires_at, created_at \
             FROM lucid_auth_verifications WHERE purpose = $1 AND identifier = $2",
        )
        .bind(purpose)
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.map(VerificationValue::from))
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
