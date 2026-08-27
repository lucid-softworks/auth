use super::{SqliteFilter, SqliteFilterOperator, SqliteFindOptions, SqliteStore, codec};
use crate::{ApiKey, ApiKeyStore, ApiKeyUseOutcome, AuthError, store::DatabaseCreate};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;

#[async_trait]
impl ApiKeyStore for SqliteStore {
    async fn create_api_key(&self, key: DatabaseCreate<ApiKey>) -> Result<ApiKey, AuthError> {
        let (key, id) = key.into_parts(self)?;
        let record = codec::api_key_create_record(self, &key, &id)?;
        codec::decode_api_key(self.insert_record("apikey", record).await?)
    }

    async fn find_api_key(&self, id: &str) -> Result<Option<ApiKey>, AuthError> {
        find(self, "id", id).await
    }

    async fn find_api_key_by_hash(&self, hash: &str) -> Result<Option<ApiKey>, AuthError> {
        find(self, "key", hash).await
    }

    async fn list_api_keys(
        &self,
        reference_id: &str,
        config_id: Option<&str>,
    ) -> Result<Vec<ApiKey>, AuthError> {
        let mut filters = vec![eq("referenceId", reference_id)];
        if let Some(config_id) = config_id {
            filters.push(eq("configId", config_id));
        }
        self.find_records("apikey", &filters, &SqliteFindOptions::default())
            .await?
            .into_iter()
            .map(codec::decode_api_key)
            .collect()
    }

    async fn update_api_key(&self, key: ApiKey) -> Result<Option<ApiKey>, AuthError> {
        let values = codec::api_key_update_record(self, &key)?;
        self.update_record("apikey", &[eq("id", &key.id)], values)
            .await?
            .map(codec::decode_api_key)
            .transpose()
    }

    async fn delete_api_key(&self, id: &str) -> Result<bool, AuthError> {
        Ok(self.delete_records("apikey", &[eq("id", id)]).await? == 1)
    }

    async fn delete_expired_api_keys(&self, now: DateTime<Utc>) -> Result<u64, AuthError> {
        let mut filter = SqliteFilter::equal("expiresAt", json!(now));
        filter.operator = SqliteFilterOperator::Lt;
        self.delete_records("apikey", &[filter]).await
    }

    async fn record_api_key_use(
        &self,
        id: &str,
        now: DateTime<Utc>,
        rate_limit_enabled: bool,
    ) -> Result<ApiKeyUseOutcome, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        let Some(record) = super::query::execute::find_one(
            &mut transaction,
            schema,
            "apikey",
            &[eq("id", id)],
            &[],
        )
        .await?
        else {
            transaction.rollback().await.map_err(storage)?;
            return Ok(ApiKeyUseOutcome::Invalid);
        };
        let mut key = codec::decode_api_key(record)?;
        let outcome = evaluate(&mut key, now, rate_limit_enabled);
        if matches!(
            outcome,
            ApiKeyUseOutcome::Allowed(_) | ApiKeyUseOutcome::RateLimited { .. }
        ) {
            let values = codec::api_key_update_record(self, &key)?;
            super::query::execute::update_one(
                &mut transaction,
                schema,
                "apikey",
                &[eq("id", id)],
                values,
            )
            .await?;
            transaction.commit().await.map_err(storage)?;
        } else {
            transaction.rollback().await.map_err(storage)?;
        }
        Ok(outcome)
    }
}

fn evaluate(key: &mut ApiKey, now: DateTime<Utc>, rate_limit_enabled: bool) -> ApiKeyUseOutcome {
    if !key.enabled || key.expires_at.is_some_and(|expires| expires < now) {
        return ApiKeyUseOutcome::Invalid;
    }
    refill(key, now);
    if key.remaining == Some(0) {
        return ApiKeyUseOutcome::UsageExceeded;
    }
    if let Some(remaining) = &mut key.remaining {
        *remaining -= 1;
    }
    let retry = retry_after(key, now, rate_limit_enabled);
    if retry.is_none() {
        record_request(key, now, rate_limit_enabled);
    }
    key.updated_at = now;
    retry.map_or_else(
        || ApiKeyUseOutcome::Allowed(Box::new(key.clone())),
        |retry_after_milliseconds| ApiKeyUseOutcome::RateLimited {
            retry_after_milliseconds,
        },
    )
}

fn refill(key: &mut ApiKey, now: DateTime<Utc>) {
    if let (Some(interval), Some(amount), Some(_)) =
        (key.refill_interval, key.refill_amount, key.remaining)
    {
        let since = key.last_refill_at.unwrap_or(key.created_at);
        if since + Duration::milliseconds(interval) < now {
            key.remaining = Some(amount);
            key.last_refill_at = Some(now);
        }
    }
}

fn retry_after(key: &ApiKey, now: DateTime<Utc>, rate_limit_enabled: bool) -> Option<i64> {
    let (Some(window), Some(max), Some(last)) = (
        key.rate_limit_time_window,
        key.rate_limit_max,
        key.last_request,
    ) else {
        return None;
    };
    if !rate_limit_enabled || !key.rate_limit_enabled {
        return None;
    }
    let elapsed = (now - last).num_milliseconds();
    (elapsed <= window && key.request_count >= max).then_some((window - elapsed).max(0))
}

fn record_request(key: &mut ApiKey, now: DateTime<Utc>, rate_limit_enabled: bool) {
    if !rate_limit_enabled || !key.rate_limit_enabled {
        key.last_request = Some(now);
        return;
    }
    if key.rate_limit_time_window.is_none() || key.rate_limit_max.is_none() {
        return;
    }
    let reset = match (key.rate_limit_time_window, key.last_request) {
        (Some(window), Some(last)) => last + Duration::milliseconds(window) < now,
        _ => true,
    };
    key.request_count = if reset {
        1
    } else {
        key.request_count.saturating_add(1)
    };
    key.last_request = Some(now);
}

async fn find(store: &SqliteStore, field: &str, value: &str) -> Result<Option<ApiKey>, AuthError> {
    store
        .find_record("apikey", &[eq(field, value)], &[])
        .await?
        .map(codec::decode_api_key)
        .transpose()
}

fn eq(field: &str, value: &str) -> SqliteFilter {
    SqliteFilter::equal(field, json!(value))
}

fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
