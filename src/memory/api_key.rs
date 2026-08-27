use super::MemoryStore;
use crate::store::DatabaseCreate;
use crate::{ApiKey, ApiKeyStore, ApiKeyUseOutcome, AuthError};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

#[async_trait]
impl ApiKeyStore for MemoryStore {
    async fn create_api_key(&self, api_key: DatabaseCreate<ApiKey>) -> Result<ApiKey, AuthError> {
        let (mut api_key, id) = api_key.into_parts(self)?;
        let mut state = self.state.write().await;
        api_key.id = self.create_id("apikey", id, state.api_keys.len())?;
        state.api_keys.insert(api_key.id.clone(), api_key.clone());
        Ok(api_key)
    }

    async fn find_api_key(&self, api_key_id: &str) -> Result<Option<ApiKey>, AuthError> {
        Ok(self.state.read().await.api_keys.get(api_key_id).cloned())
    }

    async fn find_api_key_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .api_keys
            .values()
            .find(|api_key| api_key.key_hash == key_hash)
            .cloned())
    }

    async fn list_api_keys(
        &self,
        reference_id: &str,
        config_id: Option<&str>,
    ) -> Result<Vec<ApiKey>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .api_keys
            .values()
            .filter(|api_key| {
                api_key.reference_id == reference_id
                    && config_id.is_none_or(|config_id| api_key.config_id == config_id)
            })
            .cloned()
            .collect())
    }

    async fn update_api_key(&self, api_key: ApiKey) -> Result<Option<ApiKey>, AuthError> {
        let mut state = self.state.write().await;
        if !state.api_keys.contains_key(&api_key.id) {
            return Ok(None);
        }
        state.api_keys.insert(api_key.id.clone(), api_key.clone());
        Ok(Some(api_key))
    }

    async fn delete_api_key(&self, api_key_id: &str) -> Result<bool, AuthError> {
        Ok(self
            .state
            .write()
            .await
            .api_keys
            .remove(api_key_id)
            .is_some())
    }

    async fn delete_expired_api_keys(&self, now: DateTime<Utc>) -> Result<u64, AuthError> {
        let mut state = self.state.write().await;
        let before = state.api_keys.len();
        state.api_keys.retain(|_, api_key| {
            api_key
                .expires_at
                .is_none_or(|expires_at| expires_at >= now)
        });
        Ok(u64::try_from(before - state.api_keys.len()).unwrap_or(u64::MAX))
    }

    async fn record_api_key_use(
        &self,
        api_key_id: &str,
        now: DateTime<Utc>,
        rate_limit_enabled: bool,
    ) -> Result<ApiKeyUseOutcome, AuthError> {
        let mut state = self.state.write().await;
        let Some(api_key) = state.api_keys.get_mut(api_key_id) else {
            return Ok(ApiKeyUseOutcome::Invalid);
        };
        if !api_key.enabled
            || api_key
                .expires_at
                .is_some_and(|expires_at| expires_at < now)
        {
            return Ok(ApiKeyUseOutcome::Invalid);
        }
        refill_remaining(api_key, now);
        if api_key.remaining == Some(0) {
            return Ok(ApiKeyUseOutcome::UsageExceeded);
        }
        if let Some(remaining) = &mut api_key.remaining {
            *remaining -= 1;
        }
        if let Some(retry_after_milliseconds) = rate_limit_retry(api_key, now, rate_limit_enabled) {
            return Ok(ApiKeyUseOutcome::RateLimited {
                retry_after_milliseconds,
            });
        }
        record_rate_limit(api_key, now, rate_limit_enabled);
        api_key.updated_at = now;
        Ok(ApiKeyUseOutcome::Allowed(Box::new(api_key.clone())))
    }
}

fn refill_remaining(api_key: &mut ApiKey, now: DateTime<Utc>) {
    let (Some(interval), Some(amount), Some(_)) = (
        api_key.refill_interval,
        api_key.refill_amount,
        api_key.remaining,
    ) else {
        return;
    };
    if interval == 0 || amount == 0 {
        return;
    }
    let since = api_key.last_refill_at.unwrap_or(api_key.created_at);
    if since + Duration::milliseconds(interval) < now {
        api_key.remaining = Some(amount);
        api_key.last_refill_at = Some(now);
    }
}

fn rate_limit_retry(api_key: &ApiKey, now: DateTime<Utc>, rate_limit_enabled: bool) -> Option<i64> {
    if !rate_limit_enabled || !api_key.rate_limit_enabled {
        return None;
    }
    let (Some(window), Some(max), Some(last_request)) = (
        api_key.rate_limit_time_window,
        api_key.rate_limit_max,
        api_key.last_request,
    ) else {
        return None;
    };
    let elapsed = (now - last_request).num_milliseconds();
    (elapsed <= window && api_key.request_count >= max).then_some((window - elapsed).max(0))
}

fn record_rate_limit(api_key: &mut ApiKey, now: DateTime<Utc>, rate_limit_enabled: bool) {
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
    api_key.request_count = if reset {
        1
    } else {
        api_key.request_count.saturating_add(1)
    };
    api_key.last_request = Some(now);
}
