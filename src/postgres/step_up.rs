use super::{PostgresModel, PostgresStore, storage_error};
use crate::{AuthError, StepUpAssurance, StepUpSession, StepUpStore};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{FromRow, QueryBuilder, postgres::PgRow};

#[derive(FromRow)]
struct StepUpRow {
    assurance: String,
    authenticated_at: DateTime<Utc>,
}

struct StepUpModels<'a> {
    session: PostgresModel<'a>,
    user: PostgresModel<'a>,
}

impl<'a> StepUpModels<'a> {
    fn from_store(store: &'a PostgresStore) -> Result<Self, AuthError> {
        Ok(Self {
            session: store.physical_model("session")?,
            user: store.physical_model("user")?,
        })
    }

    fn decode(&self, row: &PgRow) -> Result<StepUpSession, AuthError> {
        let state = StepUpRow::from_row(row).map_err(storage_error)?;
        Ok(StepUpSession {
            session_id: self
                .session
                .decode_id(row, "session_id")?
                .ok_or_else(|| AuthError::Storage("step-up session id is null".into()))?,
            user_id: self
                .user
                .decode_id(row, "user_id")?
                .ok_or_else(|| AuthError::Storage("step-up user id is null".into()))?,
            assurance: StepUpAssurance::parse(&state.assurance)
                .ok_or_else(|| AuthError::Storage("step-up assurance value is invalid".into()))?,
            authenticated_at: state.authenticated_at,
        })
    }
}

#[async_trait]
impl StepUpStore for PostgresStore {
    async fn upsert_step_up_session(&self, session: StepUpSession) -> Result<(), AuthError> {
        let models = StepUpModels::from_store(self)?;
        let mut query = QueryBuilder::new(
            "INSERT INTO lucid_auth_step_up_sessions \
             (session_id, user_id, assurance, authenticated_at) VALUES (",
        );
        models
            .session
            .encode("id", json!(session.session_id))?
            .push_bind(&mut query);
        query.push(", ");
        models
            .user
            .encode("id", json!(session.user_id))?
            .push_bind(&mut query);
        query
            .push(", ")
            .push_bind(session.assurance.as_str())
            .push(", ")
            .push_bind(session.authenticated_at)
            .push(
                ") \
             ON CONFLICT (session_id) DO UPDATE SET user_id = EXCLUDED.user_id, \
               assurance = EXCLUDED.assurance, authenticated_at = EXCLUDED.authenticated_at",
            );
        query
            .build()
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }

    async fn find_step_up_session(
        &self,
        session_id: &str,
    ) -> Result<Option<StepUpSession>, AuthError> {
        let models = StepUpModels::from_store(self)?;
        let mut query = QueryBuilder::new(
            "SELECT session_id, user_id, assurance, authenticated_at \
             FROM lucid_auth_step_up_sessions WHERE session_id = ",
        );
        models
            .session
            .encode("id", json!(session_id))?
            .push_bind(&mut query);
        query
            .build()
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .as_ref()
            .map(|row| models.decode(row))
            .transpose()
    }

    async fn delete_step_up_session(&self, session_id: &str) -> Result<(), AuthError> {
        let session = self.physical_model("session")?;
        let mut query =
            QueryBuilder::new("DELETE FROM lucid_auth_step_up_sessions WHERE session_id = ");
        session
            .encode("id", json!(session_id))?
            .push_bind(&mut query);
        query
            .build()
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }

    async fn delete_user_step_up_state(&self, user_id: &str) -> Result<(), AuthError> {
        let user = self.physical_model("user")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let mut sessions =
            QueryBuilder::new("DELETE FROM lucid_auth_step_up_sessions WHERE user_id = ");
        user.encode("id", json!(user_id))?.push_bind(&mut sessions);
        sessions
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let mut recovery =
            QueryBuilder::new("DELETE FROM lucid_auth_step_up_recovery_codes WHERE user_id = ");
        user.encode("id", json!(user_id))?.push_bind(&mut recovery);
        recovery
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)
    }

    async fn replace_step_up_recovery_codes(
        &self,
        user_id: &str,
        code_hashes: Vec<String>,
    ) -> Result<(), AuthError> {
        let user = self.physical_model("user")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let mut delete =
            QueryBuilder::new("DELETE FROM lucid_auth_step_up_recovery_codes WHERE user_id = ");
        user.encode("id", json!(user_id))?.push_bind(&mut delete);
        delete
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        for hash in code_hashes {
            let mut insert = QueryBuilder::new(
                "INSERT INTO lucid_auth_step_up_recovery_codes \
                 (user_id, code_hash, created_at) VALUES (",
            );
            user.encode("id", json!(user_id))?.push_bind(&mut insert);
            insert.push(", ").push_bind(hash).push(", NOW())");
            insert
                .build()
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
        }
        transaction.commit().await.map_err(storage_error)
    }

    async fn consume_step_up_recovery_code(
        &self,
        user_id: &str,
        code_hash: &str,
    ) -> Result<bool, AuthError> {
        let user = self.physical_model("user")?;
        let mut query = QueryBuilder::new(
            "DELETE FROM lucid_auth_step_up_recovery_codes \
             WHERE user_id = ",
        );
        user.encode("id", json!(user_id))?.push_bind(&mut query);
        query.push(" AND code_hash = ").push_bind(code_hash);
        query
            .build()
            .execute(&self.pool)
            .await
            .map(|result| result.rows_affected() == 1)
            .map_err(storage_error)
    }

    async fn step_up_recovery_code_count(&self, user_id: &str) -> Result<usize, AuthError> {
        let user = self.physical_model("user")?;
        let mut query = QueryBuilder::new(
            "SELECT COUNT(*) FROM lucid_auth_step_up_recovery_codes WHERE user_id = ",
        );
        user.encode("id", json!(user_id))?.push_bind(&mut query);
        let count = query
            .build_query_scalar::<i64>()
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)?;
        usize::try_from(count).map_err(|_| AuthError::Storage("invalid recovery-code count".into()))
    }

    async fn delete_step_up_recovery_codes(&self, user_id: &str) -> Result<(), AuthError> {
        let user = self.physical_model("user")?;
        let mut query =
            QueryBuilder::new("DELETE FROM lucid_auth_step_up_recovery_codes WHERE user_id = ");
        user.encode("id", json!(user_id))?.push_bind(&mut query);
        query
            .build()
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }
}
