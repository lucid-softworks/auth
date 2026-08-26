use super::{PostgresStore, storage_error};
use crate::{AuthError, OperatorSecurityStore};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::QueryBuilder;
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
        owner_role: &str,
        password_hash: String,
    ) -> Result<bool, AuthError> {
        let models = RecoveryModels::from_store(self)?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        if owner_ids(&mut transaction, &models.user, owner_role).await? != [user_id] {
            return Ok(false);
        }
        let now = Utc::now();
        replace_credential(
            &mut transaction,
            &models.account,
            user_id,
            password_hash,
            now,
        )
        .await?;
        clear_user_restrictions(&mut transaction, &models.user, user_id, now).await?;
        clear_bound_security_state(&mut transaction, &models, user_id).await?;
        mark_temporary(&mut transaction, user_id).await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(true)
    }
}

struct RecoveryModels<'a> {
    user: super::PostgresModel<'a>,
    account: super::PostgresModel<'a>,
    session: Option<super::PostgresModel<'a>>,
    passkey: Option<super::PostgresModel<'a>>,
    api_key: Option<super::PostgresModel<'a>>,
}

impl<'a> RecoveryModels<'a> {
    fn from_store(store: &'a PostgresStore) -> Result<Self, AuthError> {
        Ok(Self {
            user: store.physical_model("user")?,
            account: store.physical_model("account")?,
            session: store.physical_model_if_present("session")?,
            passkey: store.physical_model_if_present("passkey")?,
            api_key: store.physical_model_if_present("apikey")?,
        })
    }
}

async fn owner_ids(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user: &super::PostgresModel<'_>,
    owner_role: &str,
) -> Result<Vec<Uuid>, AuthError> {
    let mut query = QueryBuilder::new("SELECT \"id\" FROM ");
    query
        .push(user.quoted_table())
        .push(" WHERE ")
        .push(user.quoted_column("role")?)
        .push(" = ")
        .push_bind(owner_role.to_owned());
    if user.has_field("isAnonymous") {
        query
            .push(" AND ")
            .push(user.quoted_column("isAnonymous")?)
            .push(" = FALSE");
    }
    query.push(" FOR UPDATE");
    query
        .build_query_scalar::<Uuid>()
        .fetch_all(&mut **transaction)
        .await
        .map_err(storage_error)
}

async fn replace_credential(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account: &super::PostgresModel<'_>,
    user_id: Uuid,
    password_hash: String,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    let writes = account.encode_fields([
        ("password", Value::String(password_hash)),
        ("updatedAt", json!(now.to_rfc3339())),
    ])?;
    let mut query = super::rows::update_query(account, writes);
    query
        .push(" WHERE ")
        .push(account.quoted_column("userId")?)
        .push(" = ")
        .push_bind(user_id)
        .push(" AND ")
        .push(account.quoted_column("providerId")?)
        .push(" = ")
        .push_bind("credential".to_owned());
    let result = query
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(storage_error)?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AuthError::CredentialAccountNotFound)
    }
}

async fn clear_user_restrictions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user: &super::PostgresModel<'_>,
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    let writes = user.encode_fields([
        ("banned", json!(false)),
        ("banReason", Value::Null),
        ("banExpires", Value::Null),
        ("updatedAt", json!(now.to_rfc3339())),
    ])?;
    let mut query = super::rows::update_query(user, writes);
    query.push(" WHERE \"id\" = ").push_bind(user_id);
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

async fn clear_bound_security_state(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    models: &RecoveryModels<'_>,
    user_id: Uuid,
) -> Result<(), AuthError> {
    if let Some(session) = &models.session {
        delete_by_uuid(transaction, session, "userId", user_id).await?;
    }
    if let Some(passkey) = &models.passkey {
        delete_by_uuid(transaction, passkey, "userId", user_id).await?;
    }
    if let Some(api_key) = &models.api_key {
        delete_by_text(transaction, api_key, "referenceId", user_id.to_string()).await?;
    }
    Ok(())
}

async fn mark_temporary(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> Result<(), AuthError> {
    sqlx::query(
        "INSERT INTO lucid_auth_operator_temporary_passwords (user_id) VALUES ($1) \
         ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(user_id)
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(storage_error)
}

async fn delete_by_uuid(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    model: &super::PostgresModel<'_>,
    logical_field: &str,
    value: Uuid,
) -> Result<(), AuthError> {
    let mut query = QueryBuilder::new("DELETE FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column(logical_field)?)
        .push(" = ")
        .push_bind(value);
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

async fn delete_by_text(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    model: &super::PostgresModel<'_>,
    logical_field: &str,
    value: String,
) -> Result<(), AuthError> {
    let mut query = QueryBuilder::new("DELETE FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column(logical_field)?)
        .push(" = ")
        .push_bind(value);
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}
