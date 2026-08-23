use super::{PostgresStore, storage_error};
use crate::{AuthError, OperatorSecurityStore};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
impl OperatorSecurityStore for PostgresStore {
    async fn is_temporary_password(&self, user_id: Uuid) -> Result<bool, AuthError> {
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM lucid_auth_operator_temporary_passwords WHERE user_id = $1)",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)
    }

    async fn set_temporary_password(
        &self,
        user_id: Uuid,
        temporary: bool,
    ) -> Result<(), AuthError> {
        let query = if temporary {
            "INSERT INTO lucid_auth_operator_temporary_passwords (user_id) VALUES ($1) \
             ON CONFLICT (user_id) DO NOTHING"
        } else {
            "DELETE FROM lucid_auth_operator_temporary_passwords WHERE user_id = $1"
        };
        sqlx::query(query)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }

    async fn recover_sole_owner(
        &self,
        user_id: Uuid,
        password_hash: String,
    ) -> Result<bool, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let owners = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM lucid_auth_users \
             WHERE role = 'owner' AND is_anonymous = FALSE FOR UPDATE",
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if owners.as_slice() != [user_id] {
            return Ok(false);
        }
        let account = sqlx::query(
            "UPDATE lucid_auth_accounts SET password_hash = $2, updated_at = NOW() \
             WHERE user_id = $1 AND provider_id = 'credential'",
        )
        .bind(user_id)
        .bind(password_hash)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        if account.rows_affected() != 1 {
            return Err(AuthError::CredentialAccountNotFound);
        }
        sqlx::query(
            "UPDATE lucid_auth_users SET banned = FALSE, ban_reason = NULL, \
             ban_expires = NULL, updated_at = NOW() WHERE id = $1",
        )
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        sqlx::query("DELETE FROM lucid_auth_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        sqlx::query("DELETE FROM lucid_auth_passkeys WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let api_keys_exist =
            sqlx::query_scalar::<_, bool>("SELECT to_regclass('lucid_auth_api_keys') IS NOT NULL")
                .fetch_one(&mut *transaction)
                .await
                .map_err(storage_error)?;
        if api_keys_exist {
            sqlx::query("DELETE FROM lucid_auth_api_keys WHERE reference_id = $1")
                .bind(user_id.to_string())
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
        }
        sqlx::query(
            "INSERT INTO lucid_auth_operator_temporary_passwords (user_id) VALUES ($1) \
             ON CONFLICT (user_id) DO NOTHING",
        )
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(true)
    }
}
