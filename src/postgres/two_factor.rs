mod codec;

use super::{PostgresModel, PostgresStore, storage_error};
use crate::{AuthError, TwoFactorRecord, TwoFactorStore};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Postgres, QueryBuilder};

use codec::{decode_two_factor, two_factor_update_writes, two_factor_writes};

impl PostgresStore {
    fn two_factor_model(&self) -> Result<PostgresModel<'_>, AuthError> {
        self.physical_model("twoFactor")
    }
}

#[async_trait]
impl TwoFactorStore for PostgresStore {
    async fn two_factor_enabled(&self, user_id: &str) -> Result<bool, AuthError> {
        let model = self.user_model()?;
        let mut query = QueryBuilder::<Postgres>::new("SELECT ");
        query
            .push(model.quoted_column("twoFactorEnabled")?)
            .push(" FROM ")
            .push(model.quoted_table())
            .push(" WHERE \"id\" = ");
        model.encode("id", json!(user_id))?.push_bind(&mut query);
        query
            .build_query_scalar::<Option<bool>>()
            .fetch_optional(&self.pool)
            .await
            .map(|value| value.flatten().unwrap_or(false))
            .map_err(storage_error)
    }

    async fn set_two_factor_enabled(&self, user_id: &str, enabled: bool) -> Result<(), AuthError> {
        let model = self.user_model()?;
        let writes = model.encode_fields([("twoFactorEnabled", json!(enabled))])?;
        let mut query = super::rows::update_query(&model, writes);
        query.push(" WHERE \"id\" = ");
        model.encode("id", json!(user_id))?.push_bind(&mut query);
        let result = query
            .build()
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    async fn find_two_factor(&self, user_id: &str) -> Result<Option<TwoFactorRecord>, AuthError> {
        let model = self.two_factor_model()?;
        let mut query = select_query(&model);
        push_user_predicate(&mut query, &model, user_id)?;
        decode_optional(&model, query, &self.pool).await
    }

    async fn upsert_two_factor(
        &self,
        record: TwoFactorRecord,
    ) -> Result<TwoFactorRecord, AuthError> {
        let user_model = self.user_model()?;
        let model = self.two_factor_model()?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let mut lock = QueryBuilder::<Postgres>::new("SELECT \"id\" FROM ");
        lock.push(user_model.quoted_table())
            .push(" WHERE \"id\" = ");
        user_model
            .encode("id", json!(record.user_id))?
            .push_bind(&mut lock);
        lock.push(" FOR UPDATE");
        if lock
            .build()
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?
            .is_none()
        {
            return Err(AuthError::NotFound);
        }

        let updates = two_factor_update_writes(&model, &record)?;
        let mut update = super::rows::update_query(&model, updates);
        push_user_predicate(&mut update, &model, &record.user_id)?;
        update.push(" RETURNING ").push(model.all_projection());
        if let Some(row) = update
            .build()
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?
        {
            let stored = decode_two_factor(&model, &row)?;
            transaction.commit().await.map_err(storage_error)?;
            return Ok(stored);
        }

        let writes = two_factor_writes(&model, &record)?;
        let mut insert = super::rows::insert_query(&model, writes);
        let row = insert
            .build()
            .fetch_one(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let stored = decode_two_factor(&model, &row)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(stored)
    }

    async fn delete_two_factor(&self, user_id: &str) -> Result<(), AuthError> {
        let user_model = self.user_model()?;
        let model = self.two_factor_model()?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let mut delete = QueryBuilder::<Postgres>::new("DELETE FROM ");
        delete.push(model.quoted_table());
        push_user_predicate(&mut delete, &model, user_id)?;
        delete
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let writes = user_model.encode_fields([("twoFactorEnabled", json!(false))])?;
        let mut update = super::rows::update_query(&user_model, writes);
        update.push(" WHERE \"id\" = ");
        user_model
            .encode("id", json!(user_id))?
            .push_bind(&mut update);
        update
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)
    }

    async fn replace_backup_codes(
        &self,
        user_id: &str,
        expected: &str,
        replacement: String,
    ) -> Result<bool, AuthError> {
        let model = self.two_factor_model()?;
        let writes = model.encode_fields([("backupCodes", json!(replacement))])?;
        let mut query = super::rows::update_query(&model, writes);
        push_user_predicate(&mut query, &model, user_id)?;
        query
            .push(" AND ")
            .push(model.quoted_column("backupCodes")?)
            .push(" = ");
        model
            .encode("backupCodes", json!(expected))?
            .push_bind(&mut query);
        query
            .build()
            .execute(&self.pool)
            .await
            .map(|result| result.rows_affected() == 1)
            .map_err(storage_error)
    }

    async fn complete_two_factor_enrollment(&self, user_id: &str) -> Result<bool, AuthError> {
        let user_model = self.user_model()?;
        let model = self.two_factor_model()?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let writes = model.encode_fields([("verified", json!(true))])?;
        let mut update_record = super::rows::update_query(&model, writes);
        push_user_predicate(&mut update_record, &model, user_id)?;
        let updated = update_record
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?
            .rows_affected()
            == 1;
        if !updated {
            return Ok(false);
        }
        let writes = user_model.encode_fields([("twoFactorEnabled", json!(true))])?;
        let mut update_user = super::rows::update_query(&user_model, writes);
        update_user.push(" WHERE \"id\" = ");
        user_model
            .encode("id", json!(user_id))?
            .push_bind(&mut update_user);
        update_user
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(true)
    }

    async fn record_two_factor_failure(
        &self,
        user_id: &str,
        max_attempts: u32,
        locked_until: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let max_attempts = i32::try_from(max_attempts).map_err(|_| {
            AuthError::InvalidConfiguration("two-factor attempt budget is too large".into())
        })?;
        let model = self.two_factor_model()?;
        let failures = model.quoted_column("failedVerificationCount")?;
        let locked = model.quoted_column("lockedUntil")?;
        let mut query = QueryBuilder::<Postgres>::new("UPDATE ");
        query
            .push(model.quoted_table())
            .push(" SET ")
            .push(failures)
            .push(" = ")
            .push(failures)
            .push(" + 1, ")
            .push(locked)
            .push(" = CASE WHEN ")
            .push(failures)
            .push(" + 1 >= ")
            .push_bind(max_attempts)
            .push(" THEN ")
            .push_bind(locked_until)
            .push(" ELSE ")
            .push(locked)
            .push(" END");
        push_user_predicate(&mut query, &model, user_id)?;
        query
            .push(" RETURNING ")
            .push(failures)
            .push(" >= ")
            .push_bind(max_attempts);
        query
            .build_query_scalar::<bool>()
            .fetch_optional(&self.pool)
            .await
            .map(|locked| locked.unwrap_or(false))
            .map_err(storage_error)
    }

    async fn reset_two_factor_failures(&self, user_id: &str) -> Result<(), AuthError> {
        let model = self.two_factor_model()?;
        let writes = model.encode_fields([
            ("failedVerificationCount", json!(0)),
            ("lockedUntil", serde_json::Value::Null),
        ])?;
        let mut query = super::rows::update_query(&model, writes);
        push_user_predicate(&mut query, &model, user_id)?;
        query
            .build()
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }
}

fn select_query(model: &PostgresModel<'_>) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.all_projection())
        .push(" FROM ")
        .push(model.quoted_table());
    query
}

fn push_user_predicate(
    query: &mut QueryBuilder<'static, Postgres>,
    model: &PostgresModel<'_>,
    user_id: &str,
) -> Result<(), AuthError> {
    query
        .push(" WHERE ")
        .push(model.quoted_column("userId")?)
        .push(" = ");
    model.encode("userId", json!(user_id))?.push_bind(query);
    Ok(())
}

async fn decode_optional(
    model: &PostgresModel<'_>,
    mut query: QueryBuilder<'static, Postgres>,
    pool: &sqlx::PgPool,
) -> Result<Option<TwoFactorRecord>, AuthError> {
    query
        .build()
        .fetch_optional(pool)
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| decode_two_factor(model, row))
        .transpose()
}
