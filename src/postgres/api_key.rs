use super::{PostgresStore, storage_error};
use crate::{ApiKey, ApiKeyStore, ApiKeyUseOutcome, AuthError};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sqlx::FromRow;
use uuid::Uuid;

const COLUMNS: &str = "id, config_id, name, start, prefix, key_hash, reference_id, \
    refill_interval, refill_amount, last_refill_at, enabled, rate_limit_enabled, \
    rate_limit_time_window, rate_limit_max, request_count, remaining, last_request, \
    expires_at, permissions, metadata, created_at, updated_at";

#[derive(FromRow)]
struct ApiKeyRow {
    id: Uuid,
    config_id: String,
    name: Option<String>,
    start: Option<String>,
    prefix: Option<String>,
    key_hash: String,
    reference_id: String,
    refill_interval: Option<i64>,
    refill_amount: Option<i64>,
    last_refill_at: Option<DateTime<Utc>>,
    enabled: bool,
    rate_limit_enabled: bool,
    rate_limit_time_window: Option<i64>,
    rate_limit_max: Option<i64>,
    request_count: i64,
    remaining: Option<i64>,
    last_request: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    permissions: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
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
            refill_interval: row.refill_interval,
            refill_amount: row.refill_amount,
            last_refill_at: row.last_refill_at,
            enabled: row.enabled,
            rate_limit_enabled: row.rate_limit_enabled,
            rate_limit_time_window: row.rate_limit_time_window,
            rate_limit_max: row.rate_limit_max,
            request_count: row.request_count,
            remaining: row.remaining,
            last_request: row.last_request,
            expires_at: row.expires_at,
            permissions: row
                .permissions
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| AuthError::Storage(error.to_string()))?,
            metadata: row.metadata,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[async_trait]
impl ApiKeyStore for PostgresStore {
    async fn create_api_key(&self, api_key: ApiKey) -> Result<ApiKey, AuthError> {
        let permissions = api_key
            .permissions
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| AuthError::Storage(error.to_string()))?;
        sqlx::query_as::<_, ApiKeyRow>(&format!(
            "INSERT INTO lucid_auth_api_keys ({COLUMNS}) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22) \
             RETURNING {COLUMNS}"
        ))
        .bind(api_key.id)
        .bind(api_key.config_id)
        .bind(api_key.name)
        .bind(api_key.start)
        .bind(api_key.prefix)
        .bind(api_key.key_hash)
        .bind(api_key.reference_id)
        .bind(api_key.refill_interval)
        .bind(api_key.refill_amount)
        .bind(api_key.last_refill_at)
        .bind(api_key.enabled)
        .bind(api_key.rate_limit_enabled)
        .bind(api_key.rate_limit_time_window)
        .bind(api_key.rate_limit_max)
        .bind(api_key.request_count)
        .bind(api_key.remaining)
        .bind(api_key.last_request)
        .bind(api_key.expires_at)
        .bind(permissions)
        .bind(api_key.metadata)
        .bind(api_key.created_at)
        .bind(api_key.updated_at)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?
        .try_into()
    }

    async fn find_api_key(&self, api_key_id: Uuid) -> Result<Option<ApiKey>, AuthError> {
        fetch_optional(&self.pool, "id = $1", api_key_id).await
    }

    async fn find_api_key_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>, AuthError> {
        sqlx::query_as::<_, ApiKeyRow>(&format!(
            "SELECT {COLUMNS} FROM lucid_auth_api_keys WHERE key_hash = $1"
        ))
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(TryInto::try_into)
        .transpose()
    }

    async fn list_api_keys(
        &self,
        reference_id: &str,
        config_id: Option<&str>,
    ) -> Result<Vec<ApiKey>, AuthError> {
        let query = format!(
            "SELECT {COLUMNS} FROM lucid_auth_api_keys WHERE reference_id = $1 \
             AND ($2::TEXT IS NULL OR config_id = $2)"
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

    async fn update_api_key(&self, api_key: ApiKey) -> Result<Option<ApiKey>, AuthError> {
        let permissions = api_key
            .permissions
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| AuthError::Storage(error.to_string()))?;
        sqlx::query_as::<_, ApiKeyRow>(&format!(
            "UPDATE lucid_auth_api_keys SET name=$2, refill_interval=$3, refill_amount=$4, \
             last_refill_at=$5, enabled=$6, rate_limit_enabled=$7, rate_limit_time_window=$8, \
             rate_limit_max=$9, request_count=$10, remaining=$11, last_request=$12, \
             expires_at=$13, permissions=$14, metadata=$15, updated_at=$16 \
             WHERE id=$1 RETURNING {COLUMNS}"
        ))
        .bind(api_key.id)
        .bind(api_key.name)
        .bind(api_key.refill_interval)
        .bind(api_key.refill_amount)
        .bind(api_key.last_refill_at)
        .bind(api_key.enabled)
        .bind(api_key.rate_limit_enabled)
        .bind(api_key.rate_limit_time_window)
        .bind(api_key.rate_limit_max)
        .bind(api_key.request_count)
        .bind(api_key.remaining)
        .bind(api_key.last_request)
        .bind(api_key.expires_at)
        .bind(permissions)
        .bind(api_key.metadata)
        .bind(api_key.updated_at)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(TryInto::try_into)
        .transpose()
    }

    async fn delete_api_key(&self, api_key_id: Uuid) -> Result<bool, AuthError> {
        sqlx::query("DELETE FROM lucid_auth_api_keys WHERE id = $1")
            .bind(api_key_id)
            .execute(&self.pool)
            .await
            .map(|result| result.rows_affected() == 1)
            .map_err(storage_error)
    }

    async fn delete_expired_api_keys(&self, now: DateTime<Utc>) -> Result<u64, AuthError> {
        sqlx::query("DELETE FROM lucid_auth_api_keys WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map(|result| result.rows_affected())
            .map_err(storage_error)
    }

    async fn record_api_key_use(
        &self,
        api_key_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<ApiKeyUseOutcome, AuthError> {
        claim_usage(self, api_key_id, now).await
    }
}

async fn fetch_optional(
    pool: &sqlx::PgPool,
    predicate: &str,
    id: Uuid,
) -> Result<Option<ApiKey>, AuthError> {
    sqlx::query_as::<_, ApiKeyRow>(&format!(
        "SELECT {COLUMNS} FROM lucid_auth_api_keys WHERE {predicate}"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(storage_error)?
    .map(TryInto::try_into)
    .transpose()
}

async fn claim_usage(
    store: &PostgresStore,
    api_key_id: Uuid,
    now: DateTime<Utc>,
) -> Result<ApiKeyUseOutcome, AuthError> {
    let mut transaction = store.pool.begin().await.map_err(storage_error)?;
    let row = sqlx::query_as::<_, ApiKeyRow>(&format!(
        "SELECT {COLUMNS} FROM lucid_auth_api_keys WHERE id = $1 FOR UPDATE"
    ))
    .bind(api_key_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(storage_error)?;
    let api_key: Option<ApiKey> = row.map(TryInto::try_into).transpose()?;
    let Some(mut api_key) = api_key else {
        return Ok(ApiKeyUseOutcome::Invalid);
    };
    if !api_key.enabled
        || api_key
            .expires_at
            .is_some_and(|expires_at| expires_at < now)
    {
        return Ok(ApiKeyUseOutcome::Invalid);
    }
    refill(&mut api_key, now);
    if api_key.remaining == Some(0) {
        return Ok(ApiKeyUseOutcome::UsageExceeded);
    }
    if let Some(remaining) = &mut api_key.remaining {
        *remaining -= 1;
    }
    let retry = retry_after(&api_key, now);
    if retry.is_none() {
        record_request(&mut api_key, now);
    }
    api_key.updated_at = now;
    persist_usage(&mut transaction, &api_key).await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(match retry {
        Some(retry_after_milliseconds) => ApiKeyUseOutcome::RateLimited {
            retry_after_milliseconds,
        },
        None => ApiKeyUseOutcome::Allowed(Box::new(api_key)),
    })
}

fn refill(api_key: &mut ApiKey, now: DateTime<Utc>) {
    if let (Some(interval), Some(amount), Some(_)) = (
        api_key.refill_interval,
        api_key.refill_amount,
        api_key.remaining,
    ) {
        let since = api_key.last_refill_at.unwrap_or(api_key.created_at);
        if since + Duration::milliseconds(interval) < now {
            api_key.remaining = Some(amount);
            api_key.last_refill_at = Some(now);
        }
    }
}

fn retry_after(api_key: &ApiKey, now: DateTime<Utc>) -> Option<i64> {
    let (Some(window), Some(max), Some(last)) = (
        api_key.rate_limit_time_window,
        api_key.rate_limit_max,
        api_key.last_request,
    ) else {
        return None;
    };
    if !api_key.rate_limit_enabled {
        return None;
    }
    let elapsed = (now - last).num_milliseconds();
    (elapsed <= window && api_key.request_count >= max).then_some((window - elapsed).max(0))
}

fn record_request(api_key: &mut ApiKey, now: DateTime<Utc>) {
    if !api_key.rate_limit_enabled {
        api_key.last_request = Some(now);
        return;
    }
    if api_key.rate_limit_time_window.is_none() || api_key.rate_limit_max.is_none() {
        return;
    }
    let reset = match (api_key.rate_limit_time_window, api_key.last_request) {
        (Some(window), Some(last)) => last + Duration::milliseconds(window) < now,
        _ => true,
    };
    api_key.request_count = if reset { 1 } else { api_key.request_count + 1 };
    api_key.last_request = Some(now);
}

async fn persist_usage(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    api_key: &ApiKey,
) -> Result<(), AuthError> {
    sqlx::query(
        "UPDATE lucid_auth_api_keys SET remaining=$2, last_refill_at=$3, request_count=$4, \
         last_request=$5, updated_at=$6 WHERE id=$1",
    )
    .bind(api_key.id)
    .bind(api_key.remaining)
    .bind(api_key.last_refill_at)
    .bind(api_key.request_count)
    .bind(api_key.last_request)
    .bind(api_key.updated_at)
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(storage_error)
}
