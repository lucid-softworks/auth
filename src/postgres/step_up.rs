use super::{PostgresStore, storage_error};
use crate::{AuthError, StepUpAssurance, StepUpSession, StepUpStore};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(FromRow)]
struct StepUpRow {
    session_id: Uuid,
    user_id: Uuid,
    assurance: String,
    authenticated_at: DateTime<Utc>,
}

impl TryFrom<StepUpRow> for StepUpSession {
    type Error = AuthError;

    fn try_from(row: StepUpRow) -> Result<Self, Self::Error> {
        Ok(Self {
            session_id: row.session_id,
            user_id: row.user_id,
            assurance: StepUpAssurance::parse(&row.assurance)
                .ok_or_else(|| AuthError::Storage("step-up assurance value is invalid".into()))?,
            authenticated_at: row.authenticated_at,
        })
    }
}

#[async_trait]
impl StepUpStore for PostgresStore {
    async fn upsert_step_up_session(&self, session: StepUpSession) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO lucid_auth_step_up_sessions \
             (session_id, user_id, assurance, authenticated_at) VALUES ($1,$2,$3,$4) \
             ON CONFLICT (session_id) DO UPDATE SET user_id = EXCLUDED.user_id, \
               assurance = EXCLUDED.assurance, authenticated_at = EXCLUDED.authenticated_at",
        )
        .bind(session.session_id)
        .bind(session.user_id)
        .bind(session.assurance.as_str())
        .bind(session.authenticated_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
    }

    async fn find_step_up_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<StepUpSession>, AuthError> {
        sqlx::query_as::<_, StepUpRow>(
            "SELECT session_id, user_id, assurance, authenticated_at \
             FROM lucid_auth_step_up_sessions WHERE session_id = $1",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(TryInto::try_into)
        .transpose()
    }

    async fn delete_step_up_session(&self, session_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM lucid_auth_step_up_sessions WHERE session_id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }

    async fn delete_user_step_up_state(&self, user_id: Uuid) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        sqlx::query("DELETE FROM lucid_auth_step_up_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        sqlx::query("DELETE FROM lucid_auth_step_up_recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)
    }

    async fn replace_step_up_recovery_codes(
        &self,
        user_id: Uuid,
        code_hashes: Vec<String>,
    ) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        sqlx::query("DELETE FROM lucid_auth_step_up_recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        for hash in code_hashes {
            sqlx::query(
                "INSERT INTO lucid_auth_step_up_recovery_codes \
                 (user_id, code_hash, created_at) VALUES ($1,$2,NOW())",
            )
            .bind(user_id)
            .bind(hash)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        }
        transaction.commit().await.map_err(storage_error)
    }

    async fn consume_step_up_recovery_code(
        &self,
        user_id: Uuid,
        code_hash: &str,
    ) -> Result<bool, AuthError> {
        sqlx::query(
            "DELETE FROM lucid_auth_step_up_recovery_codes \
             WHERE user_id = $1 AND code_hash = $2",
        )
        .bind(user_id)
        .bind(code_hash)
        .execute(&self.pool)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(storage_error)
    }

    async fn step_up_recovery_code_count(&self, user_id: Uuid) -> Result<usize, AuthError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_step_up_recovery_codes WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;
        usize::try_from(count).map_err(|_| AuthError::Storage("invalid recovery-code count".into()))
    }

    async fn delete_step_up_recovery_codes(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM lucid_auth_step_up_recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }
}
