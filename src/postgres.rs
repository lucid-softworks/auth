use crate::{AuthError, AuthSession, AuthStore, AuthUser, PasskeyDeleteOutcome, StoredPasskey};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

mod access;
mod api_key;
mod migrate;
mod plugin;
mod rows;
mod security;
mod user;
mod verification;

use rows::{PasskeyRow, SessionRow, UserRow};

/// PostgreSQL/SQLx persistence adapter.
#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn load_user_by_id(&self, id: Uuid) -> Result<Option<AuthUser>, AuthError> {
        user::load_by_id(&self.pool, id).await
    }
}

#[async_trait]
impl AuthStore for PostgresStore {
    async fn create_password_user(
        &self,
        user: AuthUser,
        password_hash: String,
    ) -> Result<AuthUser, AuthError> {
        user::create_password_user(&self.pool, user, password_hash).await
    }

    async fn upsert_password_user(
        &self,
        user: AuthUser,
        password_hash: String,
    ) -> Result<AuthUser, AuthError> {
        let must_change_password = user.must_change_password;
        let configured_password_hash = password_hash.clone();
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let stored = sqlx::query_as::<_, UserRow>(
            "INSERT INTO lucid_auth_users \
             (id, username, display_username, name, email, email_verified, image, role, \
              is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
             ON CONFLICT (username) DO UPDATE SET \
               display_username = EXCLUDED.display_username, name = EXCLUDED.name, \
               email = EXCLUDED.email, role = EXCLUDED.role, updated_at = EXCLUDED.updated_at \
             RETURNING id, username, display_username, name, email, email_verified, image, role, \
               is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at",
        )
        .bind(user.id)
        .bind(&user.username)
        .bind(&user.display_username)
        .bind(&user.name)
        .bind(&user.email)
        .bind(user.email_verified)
        .bind(&user.image)
        .bind(&user.role)
        .bind(user.is_anonymous)
        .bind(user.must_change_password)
        .bind(user.banned)
        .bind(&user.ban_reason)
        .bind(user.ban_expires)
        .bind(user.created_at)
        .bind(user.updated_at)
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage_error)?;
        sqlx::query(
            "INSERT INTO lucid_auth_accounts \
             (id, user_id, provider_id, account_id, password_hash, created_at, updated_at) \
             VALUES ($1, $2, 'credential', $3, $4, $5, $5) \
             ON CONFLICT (user_id, provider_id) DO NOTHING",
        )
        .bind(Uuid::new_v4())
        .bind(stored.id)
        .bind(stored.id.to_string())
        .bind(password_hash)
        .bind(Utc::now())
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if must_change_password {
            sqlx::query(
                "UPDATE lucid_auth_users SET must_change_password = TRUE, updated_at = NOW() \
                 WHERE id = $1 AND EXISTS (SELECT 1 FROM lucid_auth_accounts \
                 WHERE user_id = $1 AND provider_id = 'credential' AND password_hash = $2)",
            )
            .bind(stored.id)
            .bind(configured_password_hash)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        }
        let stored = sqlx::query_as::<_, UserRow>(
            "SELECT id, username, display_username, name, email, email_verified, image, role, \
             is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at \
             FROM lucid_auth_users WHERE id = $1",
        )
        .bind(stored.id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(AuthUser::from(stored))
    }

    async fn create_anonymous_user(&self, user: AuthUser) -> Result<AuthUser, AuthError> {
        sqlx::query_as::<_, UserRow>(
            "INSERT INTO lucid_auth_users \
             (id, username, display_username, name, email, email_verified, image, role, \
              is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at) \
             VALUES ($1, NULL, NULL, $2, $3, false, NULL, $4, true, false, false, NULL, NULL, $5, $5) \
             RETURNING id, username, display_username, name, email, email_verified, image, role, \
               is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at",
        )
        .bind(user.id)
        .bind(&user.name)
        .bind(&user.email)
        .bind(&user.role)
        .bind(user.created_at)
        .fetch_one(&self.pool)
        .await
        .map(AuthUser::from)
        .map_err(storage_error)
    }

    async fn find_user_by_username(&self, username: &str) -> Result<Option<AuthUser>, AuthError> {
        sqlx::query_as::<_, UserRow>(
            "SELECT id, username, display_username, name, email, email_verified, image, role, \
             is_anonymous, must_change_password, banned, ban_reason, ban_expires, created_at, updated_at \
             FROM lucid_auth_users WHERE username = $1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.map(AuthUser::from))
        .map_err(storage_error)
    }

    async fn find_password_hash(&self, user_id: Uuid) -> Result<Option<String>, AuthError> {
        sqlx::query_scalar(
            "SELECT password_hash FROM lucid_auth_accounts \
             WHERE user_id = $1 AND provider_id = 'credential'",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)
    }

    async fn update_password_hash(
        &self,
        user_id: Uuid,
        password_hash: String,
    ) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let result = sqlx::query(
            "UPDATE lucid_auth_accounts SET password_hash = $2, updated_at = NOW() \
             WHERE user_id = $1 AND provider_id = 'credential'",
        )
        .bind(user_id)
        .bind(password_hash)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if result.rows_affected() == 0 {
            return Err(AuthError::CredentialAccountNotFound);
        }
        sqlx::query(
            "UPDATE lucid_auth_users SET must_change_password = FALSE, updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)
    }

    async fn set_password_hash(
        &self,
        user_id: Uuid,
        password_hash: String,
    ) -> Result<(), AuthError> {
        user::set_password_hash(&self.pool, user_id, password_hash).await
    }

    async fn save_passkey(&self, passkey: StoredPasskey) -> Result<StoredPasskey, AuthError> {
        sqlx::query_as::<_, PasskeyRow>(
            "INSERT INTO lucid_auth_passkeys \
             (id, user_id, name, credential_id, credential, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             RETURNING id, user_id, name, credential_id, credential, created_at, updated_at",
        )
        .bind(passkey.id)
        .bind(passkey.user_id)
        .bind(&passkey.name)
        .bind(&passkey.credential_id)
        .bind(&passkey.credential)
        .bind(passkey.created_at)
        .bind(passkey.updated_at)
        .fetch_one(&self.pool)
        .await
        .map(StoredPasskey::from)
        .map_err(|error| {
            if error
                .as_database_error()
                .is_some_and(|database| database.is_unique_violation())
            {
                AuthError::CredentialAlreadyRegistered
            } else {
                storage_error(error)
            }
        })
    }

    async fn list_passkeys(&self, user_id: Uuid) -> Result<Vec<StoredPasskey>, AuthError> {
        sqlx::query_as::<_, PasskeyRow>(
            "SELECT id, user_id, name, credential_id, credential, created_at, updated_at \
             FROM lucid_auth_passkeys WHERE user_id = $1 ORDER BY created_at",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map(|rows| rows.into_iter().map(StoredPasskey::from).collect())
        .map_err(storage_error)
    }

    async fn list_all_passkeys(&self) -> Result<Vec<StoredPasskey>, AuthError> {
        sqlx::query_as::<_, PasskeyRow>(
            "SELECT id, user_id, name, credential_id, credential, created_at, updated_at \
             FROM lucid_auth_passkeys ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await
        .map(|rows| rows.into_iter().map(StoredPasskey::from).collect())
        .map_err(storage_error)
    }

    async fn update_passkey(&self, passkey: StoredPasskey) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE lucid_auth_passkeys SET name = $2, credential = $3, updated_at = $4 \
             WHERE id = $1",
        )
        .bind(passkey.id)
        .bind(&passkey.name)
        .bind(&passkey.credential)
        .bind(passkey.updated_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
    }

    async fn update_passkey_name(
        &self,
        user_id: Uuid,
        passkey_id: Uuid,
        name: String,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        sqlx::query_as::<_, PasskeyRow>(
            "UPDATE lucid_auth_passkeys SET name = $3, updated_at = NOW() \
             WHERE id = $1 AND user_id = $2 \
             RETURNING id, user_id, name, credential_id, credential, created_at, updated_at",
        )
        .bind(passkey_id)
        .bind(user_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.map(StoredPasskey::from))
        .map_err(storage_error)
    }

    async fn delete_passkey(
        &self,
        user_id: Uuid,
        passkey_id: Uuid,
        minimum_remaining: usize,
    ) -> Result<PasskeyDeleteOutcome, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        sqlx::query("SELECT id FROM lucid_auth_users WHERE id = $1 FOR UPDATE")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let owned = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM lucid_auth_passkeys WHERE id = $1 AND user_id = $2)",
        )
        .bind(passkey_id)
        .bind(user_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if !owned {
            return Ok(PasskeyDeleteOutcome::NotFound);
        }
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_passkeys WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if count <= i64::try_from(minimum_remaining).unwrap_or(i64::MAX) {
            return Ok(PasskeyDeleteOutcome::MinimumRequired);
        }
        sqlx::query("DELETE FROM lucid_auth_passkeys WHERE id = $1 AND user_id = $2")
            .bind(passkey_id)
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let remaining = usize::try_from(count - 1).unwrap_or(usize::MAX);
        if remaining == 0 {
            sqlx::query("DELETE FROM lucid_auth_recovery_codes WHERE user_id = $1")
                .bind(user_id)
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
        }
        transaction.commit().await.map_err(storage_error)?;
        Ok(PasskeyDeleteOutcome::Deleted { remaining })
    }

    async fn delete_user_passkeys(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM lucid_auth_passkeys WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }

    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<AuthUser>, AuthError> {
        self.load_user_by_id(user_id).await
    }

    async fn create_session(&self, session: AuthSession) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO lucid_auth_sessions \
             (id, user_id, token_hash, actor_user_id, guest_grant_id, assurance, expires_at, \
              created_at, updated_at, ip_address, user_agent) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(session.id)
        .bind(session.user_id)
        .bind(&session.token_hash)
        .bind(session.actor_user_id)
        .bind(session.guest_grant_id)
        .bind(session.assurance.as_str())
        .bind(session.expires_at)
        .bind(session.created_at)
        .bind(session.updated_at)
        .bind(&session.ip_address)
        .bind(&session.user_agent)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
    }

    async fn find_session(
        &self,
        token_hash: &str,
    ) -> Result<Option<(AuthSession, AuthUser)>, AuthError> {
        let session = sqlx::query_as::<_, SessionRow>(
            "SELECT id, user_id, token_hash, actor_user_id, guest_grant_id, assurance, \
             expires_at, created_at, updated_at, ip_address, user_agent \
             FROM lucid_auth_sessions WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(AuthSession::from);
        let Some(session) = session else {
            return Ok(None);
        };
        let user = self.load_user_by_id(session.user_id).await?;
        Ok(user.map(|user| (session, user)))
    }

    async fn delete_session(&self, token_hash: &str) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM lucid_auth_sessions WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }

    async fn delete_expired_sessions(&self, now: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM lucid_auth_sessions WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }
}

fn storage_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(error.to_string())
}
