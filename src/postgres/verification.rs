use super::{PostgresModel, PostgresStore, storage_error};
use crate::store::DatabaseCreate;
use crate::{AuthError, VerificationStore, VerificationValue};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Postgres, QueryBuilder, postgres::PgRow};

#[async_trait]
impl VerificationStore for PostgresStore {
    async fn create_verification(
        &self,
        value: DatabaseCreate<VerificationValue>,
    ) -> Result<VerificationValue, AuthError> {
        let (value, id) = value.into_parts(self)?;
        let model = self.physical_model("verification")?;
        let writes = verification_writes(&model, &value, &id)?;
        let mut query = super::rows::insert_query(&model, writes);
        query
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)
            .and_then(|row| decode_verification(&model, &row))
    }

    async fn reserve_verification(
        &self,
        value: DatabaseCreate<VerificationValue>,
    ) -> Result<Option<VerificationValue>, AuthError> {
        let (value, id) = value.into_parts(self)?;
        let model = self.physical_model("verification")?;
        let writes = verification_writes(&model, &value, &id)?;
        let mut query = super::rows::insert_query_prefix(&model, writes);
        query
            .push(" ON CONFLICT (\"id\") DO NOTHING RETURNING ")
            .push(model.all_projection());
        query
            .build()
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)
            .and_then(|row| {
                row.as_ref()
                    .map(|row| decode_verification(&model, row))
                    .transpose()
            })
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
        consume.push(model.quoted_table()).push(" WHERE \"id\" = ");
        super::rows::push_model_value(&mut consume, &model, "id", json!(candidate.id))?;
        consume.push(" RETURNING ").push(model.all_projection());
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
        query.push(" WHERE \"id\" = ");
        super::rows::push_model_value(&mut query, &model, "id", json!(value.id))?;
        query.push(" RETURNING ").push(model.all_projection());
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
            .push(" < ");
        model
            .encode("expiresAt", json!(now.to_rfc3339()))?
            .push_bind(&mut query);
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
    id: &crate::store::PreparedDatabaseId,
) -> Result<Vec<super::PostgresWrite<'a>>, AuthError> {
    let mut values = serde_json::Map::from_iter([
        ("identifier".into(), json!(value.identifier)),
        ("value".into(), json!(value.value)),
        ("expiresAt".into(), json!(value.expires_at.to_rfc3339())),
        ("createdAt".into(), json!(value.created_at.to_rfc3339())),
        ("updatedAt".into(), json!(value.updated_at.to_rfc3339())),
    ]);
    super::rows::insert_prepared_id(&mut values, id)?;
    model.encode_fields(
        values
            .iter()
            .map(|(logical, value)| (logical.as_str(), value.clone())),
    )
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
