use crate::{
    AuthError, AuthSession, AuthStore, AuthUser, EmailVerificationOutcome, PasskeyDeleteOutcome,
    PasswordResetOutcome, StoredPasskey,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

mod access;
mod api_key;
mod audit;
mod guest_capability;
mod migrate;
mod oauth;
mod operator_security;
mod passkey;
mod plugin;
mod rows;
mod security;
mod session;
mod step_up;
mod two_factor;
mod user;
mod verification;

use rows::{SessionRow, UserRow};

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
        mut user: AuthUser,
        password_hash: String,
    ) -> Result<AuthUser, AuthError> {
        user.email = user.email.to_lowercase();
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let stored = sqlx::query_as::<_, UserRow>(
            "INSERT INTO lucid_auth_users \
             (id, username, display_username, name, email, email_verified, image, additional_fields, role, \
              is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
             ON CONFLICT (username) DO UPDATE SET \
               display_username = EXCLUDED.display_username, name = EXCLUDED.name, \
               email = EXCLUDED.email, role = EXCLUDED.role, updated_at = EXCLUDED.updated_at \
             RETURNING id, username, display_username, name, email, email_verified, image, additional_fields, role, \
               is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at",
        )
        .bind(user.id)
        .bind(&user.username)
        .bind(&user.display_username)
        .bind(&user.name)
        .bind(&user.email)
        .bind(user.email_verified)
        .bind(&user.image)
        .bind(serde_json::Value::Object(user.additional_fields.clone()))
        .bind(&user.role)
        .bind(user.is_anonymous)
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
             (id, user_id, issuer, provider_id, account_id, password_hash, created_at, updated_at) \
             VALUES ($1, $2, 'local:credential', 'credential', $3, $4, $5, $5) \
             ON CONFLICT (issuer, account_id) DO NOTHING",
        )
        .bind(Uuid::new_v4())
        .bind(stored.id)
        .bind(stored.id.to_string())
        .bind(password_hash)
        .bind(Utc::now())
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        let stored = sqlx::query_as::<_, UserRow>(
            "SELECT id, username, display_username, name, email, email_verified, image, additional_fields, role, \
             is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at \
             FROM lucid_auth_users WHERE id = $1",
        )
        .bind(stored.id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(AuthUser::from(stored))
    }

    async fn create_anonymous_user(&self, mut user: AuthUser) -> Result<AuthUser, AuthError> {
        user.email = user.email.to_lowercase();
        sqlx::query_as::<_, UserRow>(
            "INSERT INTO lucid_auth_users \
             (id, username, display_username, name, email, email_verified, image, additional_fields, role, \
              is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at) \
             VALUES ($1, NULL, NULL, $2, $3, false, NULL, $4, $5, true, false, NULL, NULL, $6, $6) \
             RETURNING id, username, display_username, name, email, email_verified, image, additional_fields, role, \
               is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at",
        )
        .bind(user.id)
        .bind(&user.name)
        .bind(&user.email)
        .bind(serde_json::Value::Object(user.additional_fields))
        .bind(&user.role)
        .bind(user.created_at)
        .fetch_one(&self.pool)
        .await
        .map(AuthUser::from)
        .map_err(storage_error)
    }

    async fn create_user_without_account(&self, user: AuthUser) -> Result<AuthUser, AuthError> {
        user::create_without_account(&self.pool, user).await
    }

    async fn find_user_by_username(&self, username: &str) -> Result<Option<AuthUser>, AuthError> {
        user::load_by_username(&self.pool, username).await
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, AuthError> {
        user::load_by_email(&self.pool, email).await
    }

    async fn update_user_profile(
        &self,
        user_id: Uuid,
        update: crate::UserProfileUpdate,
    ) -> Result<Option<AuthUser>, AuthError> {
        user::update_profile(&self.pool, user_id, update).await
    }

    async fn update_user_email(
        &self,
        user_id: Uuid,
        expected_email: &str,
        new_email: &str,
        email_verified: bool,
    ) -> Result<Option<AuthUser>, AuthError> {
        user::update_email(
            &self.pool,
            user_id,
            expected_email,
            new_email,
            email_verified,
        )
        .await
    }

    async fn consume_email_verification(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<EmailVerificationOutcome, AuthError> {
        verification::consume_email_verification(&self.pool, token_hash, now).await
    }

    async fn consume_password_reset(
        &self,
        token_hash: &str,
        password_hash: String,
        now: DateTime<Utc>,
        revoke_sessions: bool,
    ) -> Result<PasswordResetOutcome, AuthError> {
        verification::consume_password_reset(
            &self.pool,
            token_hash,
            password_hash,
            now,
            revoke_sessions,
        )
        .await
    }

    async fn promote_email_owner(
        &self,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthUser>, AuthError> {
        user::promote_email_owner(&self.pool, user_id, now).await
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
        sqlx::query("UPDATE lucid_auth_users SET updated_at = NOW() WHERE id = $1")
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
        passkey::save(&self.pool, passkey).await
    }

    async fn list_passkeys(&self, user_id: Uuid) -> Result<Vec<StoredPasskey>, AuthError> {
        passkey::list_for_user(&self.pool, user_id).await
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        passkey::find_by_credential_id(&self.pool, credential_id).await
    }

    async fn find_passkey_by_id(
        &self,
        passkey_id: Uuid,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        passkey::find_by_id(&self.pool, passkey_id).await
    }

    async fn update_passkey_after_authentication(
        &self,
        passkey: StoredPasskey,
        expected_counter: u32,
    ) -> Result<bool, AuthError> {
        passkey::compare_and_swap(&self.pool, passkey, expected_counter).await
    }

    async fn update_passkey_name(
        &self,
        user_id: Uuid,
        passkey_id: Uuid,
        name: String,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        passkey::rename(&self.pool, user_id, passkey_id, name).await
    }

    async fn delete_passkey(
        &self,
        user_id: Uuid,
        passkey_id: Uuid,
        minimum_remaining: usize,
    ) -> Result<PasskeyDeleteOutcome, AuthError> {
        passkey::delete(&self.pool, user_id, passkey_id, minimum_remaining).await
    }

    async fn delete_user_passkeys(&self, user_id: Uuid) -> Result<(), AuthError> {
        passkey::delete_for_user(&self.pool, user_id).await
    }

    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<AuthUser>, AuthError> {
        self.load_user_by_id(user_id).await
    }

    async fn create_session(&self, session: AuthSession) -> Result<(), AuthError> {
        session::create(&self.pool, session).await
    }

    async fn find_session(
        &self,
        token_hash: &str,
    ) -> Result<Option<(AuthSession, AuthUser)>, AuthError> {
        session::find(&self.pool, token_hash).await
    }

    async fn update_session_fields(
        &self,
        session_id: Uuid,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<AuthSession>, AuthError> {
        session::update_fields(&self.pool, session_id, fields).await
    }

    async fn delete_session(&self, token_hash: &str) -> Result<(), AuthError> {
        session::delete(&self.pool, token_hash).await
    }

    async fn delete_expired_sessions(&self, now: DateTime<Utc>) -> Result<(), AuthError> {
        session::delete_expired(&self.pool, now).await
    }
}

fn storage_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(error.to_string())
}
