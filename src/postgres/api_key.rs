mod codec;
mod usage;

use super::{PostgresModel, PostgresStore, storage_error};
use crate::store::DatabaseCreate;
use crate::{ApiKey, ApiKeyStore, ApiKeyUseOutcome, AuthError};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Postgres, QueryBuilder};

use codec::{api_key_update_writes, api_key_writes, decode_api_key};

impl PostgresStore {
    pub(super) fn api_key_model(&self) -> Result<PostgresModel<'_>, AuthError> {
        self.physical_model("apikey")
    }
}

#[async_trait]
impl ApiKeyStore for PostgresStore {
    async fn create_api_key(&self, api_key: DatabaseCreate<ApiKey>) -> Result<ApiKey, AuthError> {
        let (api_key, id) = api_key.into_parts(self)?;
        let model = self.api_key_model()?;
        let writes = api_key_writes(&model, &api_key, &id)?;
        let mut query = super::rows::insert_query(&model, writes);
        query
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)
            .and_then(|row| decode_api_key(&model, &row))
    }

    async fn find_api_key(&self, api_key_id: &str) -> Result<Option<ApiKey>, AuthError> {
        find_by(self, "id", json!(api_key_id)).await
    }

    async fn find_api_key_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>, AuthError> {
        find_by(self, "key", json!(key_hash)).await
    }

    async fn list_api_keys(
        &self,
        reference_id: &str,
        config_id: Option<&str>,
    ) -> Result<Vec<ApiKey>, AuthError> {
        let model = self.api_key_model()?;
        let mut query = select_query(&model);
        query
            .push(" WHERE ")
            .push(model.quoted_column("referenceId")?)
            .push(" = ");
        model
            .encode("referenceId", json!(reference_id))?
            .push_bind(&mut query);
        if let Some(config_id) = config_id {
            query
                .push(" AND ")
                .push(model.quoted_column("configId")?)
                .push(" = ");
            model
                .encode("configId", json!(config_id))?
                .push_bind(&mut query);
        }
        let rows = query
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?;
        rows.iter().map(|row| decode_api_key(&model, row)).collect()
    }

    async fn update_api_key(&self, api_key: ApiKey) -> Result<Option<ApiKey>, AuthError> {
        let model = self.api_key_model()?;
        let writes = api_key_update_writes(&model, &api_key)?;
        let mut query = super::rows::update_query(&model, writes);
        query.push(" WHERE \"id\" = ");
        super::rows::push_model_value(&mut query, &model, "id", json!(api_key.id))?;
        query.push(" RETURNING ").push(model.all_projection());
        decode_optional(&model, query, &self.pool).await
    }

    async fn delete_api_key(&self, api_key_id: &str) -> Result<bool, AuthError> {
        let model = self.api_key_model()?;
        let mut query = QueryBuilder::<Postgres>::new("DELETE FROM ");
        query.push(model.quoted_table()).push(" WHERE \"id\" = ");
        super::rows::push_model_value(&mut query, &model, "id", json!(api_key_id))?;
        query
            .build()
            .execute(&self.pool)
            .await
            .map(|result| result.rows_affected() == 1)
            .map_err(storage_error)
    }

    async fn delete_expired_api_keys(&self, now: DateTime<Utc>) -> Result<u64, AuthError> {
        let model = self.api_key_model()?;
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

    async fn record_api_key_use(
        &self,
        api_key_id: &str,
        now: DateTime<Utc>,
    ) -> Result<ApiKeyUseOutcome, AuthError> {
        usage::claim_usage(self, api_key_id, now).await
    }
}

pub(super) fn select_query(model: &PostgresModel<'_>) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.all_projection())
        .push(" FROM ")
        .push(model.quoted_table());
    query
}

pub(super) async fn decode_optional(
    model: &PostgresModel<'_>,
    mut query: QueryBuilder<'static, Postgres>,
    pool: &sqlx::PgPool,
) -> Result<Option<ApiKey>, AuthError> {
    query
        .build()
        .fetch_optional(pool)
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| decode_api_key(model, row))
        .transpose()
}

async fn find_by(
    store: &PostgresStore,
    logical: &str,
    value: serde_json::Value,
) -> Result<Option<ApiKey>, AuthError> {
    let model = store.api_key_model()?;
    let mut query = select_query(&model);
    query
        .push(" WHERE ")
        .push(model.quoted_column(logical)?)
        .push(" = ");
    model.encode(logical, value)?.push_bind(&mut query);
    decode_optional(&model, query, &store.pool).await
}
