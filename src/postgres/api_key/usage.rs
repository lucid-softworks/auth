use super::{codec, select_query};
use crate::{ApiKey, ApiKeyUseOutcome, AuthError};
use chrono::{DateTime, Duration, Utc};

pub(super) async fn claim_usage(
    store: &super::super::PostgresStore,
    api_key_id: &str,
    now: DateTime<Utc>,
    rate_limit_enabled: bool,
) -> Result<ApiKeyUseOutcome, AuthError> {
    let model = store.api_key_model()?;
    let mut transaction = store
        .pool
        .begin()
        .await
        .map_err(super::super::storage_error)?;
    let mut query = select_query(&model);
    query.push(" WHERE \"id\" = ");
    super::super::rows::push_model_value(&mut query, &model, "id", serde_json::json!(api_key_id))?;
    query.push(" FOR UPDATE");
    let row = query
        .build()
        .fetch_optional(&mut *transaction)
        .await
        .map_err(super::super::storage_error)?;
    let Some(row) = row else {
        return Ok(ApiKeyUseOutcome::Invalid);
    };
    let mut api_key = codec::decode_api_key(&model, &row)?;
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
    let retry = retry_after(&api_key, now, rate_limit_enabled);
    if retry.is_none() {
        record_request(&mut api_key, now, rate_limit_enabled);
        api_key.updated_at = now;
    }
    let writes = codec::api_key_usage_writes(&model, &api_key)?;
    let mut update = super::super::rows::update_query(&model, writes);
    update.push(" WHERE \"id\" = ");
    super::super::rows::push_model_value(&mut update, &model, "id", serde_json::json!(api_key.id))?;
    update
        .build()
        .execute(&mut *transaction)
        .await
        .map_err(super::super::storage_error)?;
    transaction
        .commit()
        .await
        .map_err(super::super::storage_error)?;
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
        if interval == 0 || amount == 0 {
            return;
        }
        let since = api_key.last_refill_at.unwrap_or(api_key.created_at);
        if since + Duration::milliseconds(interval) < now {
            api_key.remaining = Some(amount);
            api_key.last_refill_at = Some(now);
        }
    }
}

fn retry_after(api_key: &ApiKey, now: DateTime<Utc>, rate_limit_enabled: bool) -> Option<i64> {
    let (Some(window), Some(max), Some(last)) = (
        api_key.rate_limit_time_window,
        api_key.rate_limit_max,
        api_key.last_request,
    ) else {
        return None;
    };
    if !rate_limit_enabled || !api_key.rate_limit_enabled {
        return None;
    }
    let elapsed = (now - last).num_milliseconds();
    (elapsed <= window && api_key.request_count >= max).then_some((window - elapsed).max(0))
}

fn record_request(api_key: &mut ApiKey, now: DateTime<Utc>, rate_limit_enabled: bool) {
    if !rate_limit_enabled || !api_key.rate_limit_enabled {
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
