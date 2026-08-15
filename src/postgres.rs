use crate::{Assurance, AuthError, AuthSession, AuthStore, AuthUser, StoredPasskey};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

mod access;
mod migrate;

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
        sqlx::query_as::<_, UserRow>(
            "SELECT id, username, display_username, name, email, email_verified, image, role, \
             is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at \
             FROM lucid_auth_users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.map(AuthUser::from))
        .map_err(storage_error)
    }
}

#[derive(FromRow)]
struct PasskeyRow {
    id: Uuid,
    user_id: Uuid,
    name: Option<String>,
    credential_id: String,
    credential: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<PasskeyRow> for StoredPasskey {
    fn from(row: PasskeyRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            name: row.name,
            credential_id: row.credential_id,
            credential: row.credential,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(FromRow)]
struct UserRow {
    id: Uuid,
    username: Option<String>,
    display_username: Option<String>,
    name: String,
    email: String,
    email_verified: bool,
    image: Option<String>,
    role: String,
    is_anonymous: bool,
    banned: bool,
    ban_reason: Option<String>,
    ban_expires: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<UserRow> for AuthUser {
    fn from(row: UserRow) -> Self {
        Self {
            id: row.id,
            username: row.username,
            display_username: row.display_username,
            name: row.name,
            email: row.email,
            email_verified: row.email_verified,
            image: row.image,
            role: row.role,
            is_anonymous: row.is_anonymous,
            banned: row.banned,
            ban_reason: row.ban_reason,
            ban_expires: row.ban_expires,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(FromRow)]
struct SessionRow {
    id: Uuid,
    user_id: Uuid,
    token_hash: String,
    actor_user_id: Option<Uuid>,
    guest_grant_id: Option<Uuid>,
    assurance: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

impl From<SessionRow> for AuthSession {
    fn from(row: SessionRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            token_hash: row.token_hash,
            actor_user_id: row.actor_user_id,
            guest_grant_id: row.guest_grant_id,
            assurance: Assurance::parse(&row.assurance),
            expires_at: row.expires_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
        }
    }
}

#[async_trait]
impl AuthStore for PostgresStore {
    async fn upsert_password_user(
        &self,
        user: AuthUser,
        password_hash: String,
    ) -> Result<AuthUser, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let stored = sqlx::query_as::<_, UserRow>(
            "INSERT INTO lucid_auth_users \
             (id, username, display_username, name, email, email_verified, image, role, \
              is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
             ON CONFLICT (username) DO UPDATE SET \
               display_username = EXCLUDED.display_username, name = EXCLUDED.name, \
               email = EXCLUDED.email, role = EXCLUDED.role, updated_at = EXCLUDED.updated_at \
             RETURNING id, username, display_username, name, email, email_verified, image, role, \
               is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at",
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
             ON CONFLICT (user_id, provider_id) DO UPDATE SET \
               password_hash = EXCLUDED.password_hash, updated_at = EXCLUDED.updated_at",
        )
        .bind(Uuid::new_v4())
        .bind(stored.id)
        .bind(stored.id.to_string())
        .bind(password_hash)
        .bind(Utc::now())
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(AuthUser::from(stored))
    }

    async fn create_anonymous_user(&self, user: AuthUser) -> Result<AuthUser, AuthError> {
        sqlx::query_as::<_, UserRow>(
            "INSERT INTO lucid_auth_users \
             (id, username, display_username, name, email, email_verified, image, role, \
              is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at) \
             VALUES ($1, NULL, NULL, $2, $3, false, NULL, $4, true, false, NULL, NULL, $5, $5) \
             RETURNING id, username, display_username, name, email, email_verified, image, role, \
               is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at",
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
             is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at \
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
