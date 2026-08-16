use super::{PostgresStore, storage_error};
use crate::{ApiKey, ApiKeyStore, AuthError};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

const API_KEY_COLUMNS: &str = "id, config_id, name, start, prefix, key_hash, reference_id, \
    enabled, rate_limit_enabled, rate_limit_window_seconds, rate_limit_max, request_count, \
    last_request, expires_at, permissions, created_at, updated_at";

#[derive(FromRow)]
struct ApiKeyRow {
    id: Uuid,
    config_id: String,
    name: String,
    start: String,
    prefix: String,
    key_hash: String,
    reference_id: Uuid,
    enabled: bool,
    rate_limit_enabled: bool,
    rate_limit_window_seconds: i64,
    rate_limit_max: i32,
    request_count: i32,
    last_request: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    permissions: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<ApiKeyRow> for ApiKey {
    type Error = AuthError;

    fn try_from(row: ApiKeyRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            config_id: row.config_id,
            name: row.name,
            start: row.start,
            prefix: row.prefix,
            key_hash: row.key_hash,
            reference_id: row.reference_id,
            enabled: row.enabled,
            rate_limit_enabled: row.rate_limit_enabled,
            rate_limit_window_seconds: row.rate_limit_window_seconds,
            rate_limit_max: row.rate_limit_max,
            request_count: row.request_count,
            last_request: row.last_request,
            expires_at: row.expires_at,
            permissions: serde_json::from_value(row.permissions)
                .map_err(|error| AuthError::Storage(error.to_string()))?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[async_trait]
impl ApiKeyStore for PostgresStore {
    async fn create_api_key(&self, api_key: ApiKey) -> Result<ApiKey, AuthError> {
        let query = format!(
            "INSERT INTO lucid_auth_api_keys \
             (id, config_id, name, start, prefix, key_hash, reference_id, enabled, \
              rate_limit_enabled, rate_limit_window_seconds, rate_limit_max, request_count, \
              last_request, expires_at, permissions, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) \
             RETURNING {API_KEY_COLUMNS}"
        );
        let permissions = serde_json::to_value(&api_key.permissions)
            .map_err(|error| AuthError::Storage(error.to_string()))?;
        sqlx::query_as::<_, ApiKeyRow>(&query)
            .bind(api_key.id)
            .bind(api_key.config_id)
            .bind(api_key.name)
            .bind(api_key.start)
            .bind(api_key.prefix)
            .bind(api_key.key_hash)
            .bind(api_key.reference_id)
            .bind(api_key.enabled)
            .bind(api_key.rate_limit_enabled)
            .bind(api_key.rate_limit_window_seconds)
            .bind(api_key.rate_limit_max)
            .bind(api_key.request_count)
            .bind(api_key.last_request)
            .bind(api_key.expires_at)
            .bind(permissions)
            .bind(api_key.created_at)
            .bind(api_key.updated_at)
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)?
            .try_into()
    }

    async fn find_api_key(&self, api_key_id: Uuid) -> Result<Option<ApiKey>, AuthError> {
        let query = format!("SELECT {API_KEY_COLUMNS} FROM lucid_auth_api_keys WHERE id = $1");
        sqlx::query_as::<_, ApiKeyRow>(&query)
            .bind(api_key_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .map(TryInto::try_into)
            .transpose()
    }

    async fn list_api_keys(
        &self,
        reference_id: Uuid,
        config_id: &str,
    ) -> Result<Vec<ApiKey>, AuthError> {
        let query = format!(
            "SELECT {API_KEY_COLUMNS} FROM lucid_auth_api_keys \
             WHERE reference_id = $1 AND config_id = $2 ORDER BY created_at DESC"
        );
        sqlx::query_as::<_, ApiKeyRow>(&query)
            .bind(reference_id)
            .bind(config_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }

    async fn revoke_api_key(
        &self,
        reference_id: Uuid,
        api_key_id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        sqlx::query(
            "UPDATE lucid_auth_api_keys SET enabled = FALSE, key_hash = '', updated_at = $3 \
             WHERE id = $1 AND reference_id = $2",
        )
        .bind(api_key_id)
        .bind(reference_id)
        .bind(revoked_at)
        .execute(&self.pool)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(storage_error)
    }

    async fn record_api_key_use(
        &self,
        api_key_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<ApiKey>, AuthError> {
        let query = format!(
            "UPDATE lucid_auth_api_keys SET \
               request_count = CASE \
                 WHEN last_request IS NULL OR \
                   last_request + make_interval(secs => rate_limit_window_seconds) <= $2 \
                 THEN 1 ELSE request_count + 1 END, \
               last_request = $2, updated_at = $2 \
             WHERE id = $1 AND enabled = TRUE AND expires_at > $2 AND ( \
               rate_limit_enabled = FALSE OR last_request IS NULL OR \
               last_request + make_interval(secs => rate_limit_window_seconds) <= $2 OR \
               request_count < rate_limit_max \
             ) RETURNING {API_KEY_COLUMNS}"
        );
        sqlx::query_as::<_, ApiKeyRow>(&query)
            .bind(api_key_id)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .map(TryInto::try_into)
            .transpose()
    }
}
