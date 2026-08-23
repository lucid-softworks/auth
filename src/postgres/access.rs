use super::{PostgresStore, SessionRow, UserRow, storage_error};
use crate::{AccessStore, AuthError, AuthSession, AuthUser};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

const USER_COLUMNS: &str = "id, username, display_username, name, email, email_verified, image, \
    role, is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at";

#[async_trait]
impl AccessStore for PostgresStore {
    async fn list_users(&self, limit: usize, offset: usize) -> Result<Vec<AuthUser>, AuthError> {
        let query = format!(
            "SELECT {USER_COLUMNS} FROM lucid_auth_users ORDER BY created_at LIMIT $1 OFFSET $2"
        );
        sqlx::query_as::<_, UserRow>(&query)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await
            .map(|rows| rows.into_iter().map(AuthUser::from).collect())
            .map_err(storage_error)
    }

    async fn count_users(&self) -> Result<i64, AuthError> {
        sqlx::query_scalar("SELECT COUNT(*) FROM lucid_auth_users")
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)
    }

    async fn count_users_by_role(&self, role: &str) -> Result<i64, AuthError> {
        sqlx::query_scalar("SELECT COUNT(*) FROM lucid_auth_users WHERE role = $1")
            .bind(role)
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)
    }

    async fn update_user_role(&self, user_id: Uuid, role: &str) -> Result<AuthUser, AuthError> {
        let query = format!(
            "UPDATE lucid_auth_users SET role = $2, updated_at = NOW() WHERE id = $1 \
             RETURNING {USER_COLUMNS}"
        );
        sqlx::query_as::<_, UserRow>(&query)
            .bind(user_id)
            .bind(role)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .map(AuthUser::from)
            .ok_or(AuthError::NotFound)
    }

    async fn update_user_ban(
        &self,
        user_id: Uuid,
        banned: bool,
        reason: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<AuthUser, AuthError> {
        let query = format!(
            "UPDATE lucid_auth_users SET banned = $2, ban_reason = $3, ban_expires = $4, \
             updated_at = NOW() WHERE id = $1 RETURNING {USER_COLUMNS}"
        );
        sqlx::query_as::<_, UserRow>(&query)
            .bind(user_id)
            .bind(banned)
            .bind(reason)
            .bind(expires_at)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .map(AuthUser::from)
            .ok_or(AuthError::NotFound)
    }

    async fn delete_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let api_key_table_exists =
            sqlx::query_scalar::<_, bool>("SELECT to_regclass('lucid_auth_api_keys') IS NOT NULL")
                .fetch_one(&mut *transaction)
                .await
                .map_err(storage_error)?;
        if api_key_table_exists {
            sqlx::query("DELETE FROM lucid_auth_api_keys WHERE reference_id = $1")
                .bind(user_id.to_string())
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
        }
        sqlx::query("DELETE FROM lucid_auth_verifications WHERE payload->>'userId' = $1")
            .bind(user_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let result = sqlx::query("DELETE FROM lucid_auth_users WHERE id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        transaction.commit().await.map_err(storage_error)
    }

    async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<AuthSession>, AuthError> {
        sqlx::query_as::<_, SessionRow>(
            "SELECT id, user_id, token_hash, actor_user_id, authentication_method, \
             expires_at, created_at, updated_at, ip_address, user_agent \
             FROM lucid_auth_sessions WHERE user_id = $1 AND expires_at > NOW() \
             ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map(|rows| rows.into_iter().map(AuthSession::from).collect())
        .map_err(storage_error)
    }

    async fn delete_session_by_id(&self, session_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM lucid_auth_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }

    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM lucid_auth_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }
}
