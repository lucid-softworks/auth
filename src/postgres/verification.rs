use super::{PostgresModel, PostgresStore, storage_error};
use crate::{AuthError, VerificationStore, VerificationValue};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Postgres, QueryBuilder, postgres::PgRow};

#[async_trait]
impl VerificationStore for PostgresStore {
    async fn create_verification(&self, value: VerificationValue) -> Result<(), AuthError> {
        let model = self.physical_model("verification")?;
        let writes = verification_writes(&model, &value)?;
        let mut query = super::rows::insert_query_prefix(&model, writes);
        query
            .build()
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }

    async fn reserve_verification(&self, value: VerificationValue) -> Result<bool, AuthError> {
        let model = self.physical_model("verification")?;
        let writes = verification_writes(&model, &value)?;
        let mut query = super::rows::insert_query_prefix(&model, writes);
        query.push(" ON CONFLICT (\"id\") DO NOTHING");
        query
            .build()
            .execute(&self.pool)
            .await
            .map(|result| result.rows_affected() == 1)
            .map_err(storage_error)
    }

    async fn find_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let model = self.physical_model("verification")?;
        let mut query = latest_query(&model, identifier)?;
        query
            .build()
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .as_ref()
            .map(|row| decode_verification(&model, row))
            .transpose()
    }

    async fn consume_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let model = self.physical_model("verification")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let mut latest = latest_query(&model, identifier)?;
        latest.push(" FOR UPDATE");
        let row = latest
            .build()
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(storage_error)?;
            return Ok(None);
        };
        let candidate = decode_verification(&model, &row)?;
        let mut consume = QueryBuilder::<Postgres>::new("DELETE FROM ");
        consume
            .push(model.quoted_table())
            .push(" WHERE \"id\" = ")
            .push_bind(candidate.id)
            .push(" RETURNING ")
            .push(model.all_projection());
        let consumed = consume
            .build()
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?
            .as_ref()
            .map(|row| decode_verification(&model, row))
            .transpose()?;
        if consumed.is_some() {
            delete_identifier(&mut transaction, &model, identifier).await?;
        }
        transaction.commit().await.map_err(storage_error)?;
        Ok(consumed)
    }

    async fn update_verification(
        &self,
        value: VerificationValue,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let model = self.physical_model("verification")?;
        let writes = model.encode_fields([
            ("value", json!(value.value)),
            ("expiresAt", json!(value.expires_at.to_rfc3339())),
            ("updatedAt", json!(value.updated_at.to_rfc3339())),
        ])?;
        let mut query = super::rows::update_query(&model, writes);
        query
            .push(" WHERE \"id\" = ")
            .push_bind(value.id)
            .push(" RETURNING ")
            .push(model.all_projection());
        query
            .build()
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .as_ref()
            .map(|row| decode_verification(&model, row))
            .transpose()
    }

    async fn delete_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let model = self.physical_model("verification")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let mut latest = latest_query(&model, identifier)?;
        latest.push(" FOR UPDATE");
        let latest = latest
            .build()
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?
            .as_ref()
            .map(|row| decode_verification(&model, row))
            .transpose()?;
        delete_identifier(&mut transaction, &model, identifier).await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(latest)
    }

    async fn delete_expired_verifications(&self, now: DateTime<Utc>) -> Result<u64, AuthError> {
        let model = self.physical_model("verification")?;
        let mut query = QueryBuilder::<Postgres>::new("DELETE FROM ");
        query
            .push(model.quoted_table())
            .push(" WHERE ")
            .push(model.quoted_column("expiresAt")?)
            .push(" < ")
            .push_bind(now);
        query
            .build()
            .execute(&self.pool)
            .await
            .map(|result| result.rows_affected())
            .map_err(storage_error)
    }
}

fn verification_writes<'a>(
    model: &'a PostgresModel<'a>,
    value: &VerificationValue,
) -> Result<Vec<super::PostgresWrite<'a>>, AuthError> {
    model.encode_fields([
        ("id", json!(value.id.to_string())),
        ("identifier", json!(value.identifier)),
        ("value", json!(value.value)),
        ("expiresAt", json!(value.expires_at.to_rfc3339())),
        ("createdAt", json!(value.created_at.to_rfc3339())),
        ("updatedAt", json!(value.updated_at.to_rfc3339())),
    ])
}

fn latest_query(
    model: &PostgresModel<'_>,
    identifier: &str,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.all_projection())
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("identifier")?)
        .push(" = ")
        .push_bind(identifier.to_owned())
        .push(" ORDER BY ")
        .push(model.quoted_column("createdAt")?)
        .push(" DESC, \"id\" DESC LIMIT 1");
    Ok(query)
}

async fn delete_identifier(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    identifier: &str,
) -> Result<(), AuthError> {
    let mut query = QueryBuilder::<Postgres>::new("DELETE FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("identifier")?)
        .push(" = ")
        .push_bind(identifier.to_owned());
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

fn decode_verification(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<VerificationValue, AuthError> {
    serde_json::from_value(serde_json::Value::Object(model.decode_all(row)?))
        .map_err(|error| AuthError::Storage(format!("invalid verification row: {error}")))
}
