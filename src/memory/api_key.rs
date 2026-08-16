use super::MemoryStore;
use crate::{ApiKey, ApiKeyStore, AuthError};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

#[async_trait]
impl ApiKeyStore for MemoryStore {
    async fn create_api_key(&self, api_key: ApiKey) -> Result<ApiKey, AuthError> {
        self.state
            .write()
            .await
            .api_keys
            .insert(api_key.id, api_key.clone());
        Ok(api_key)
    }

    async fn find_api_key(&self, api_key_id: Uuid) -> Result<Option<ApiKey>, AuthError> {
        Ok(self.state.read().await.api_keys.get(&api_key_id).cloned())
    }

    async fn list_api_keys(
        &self,
        reference_id: Uuid,
        config_id: &str,
    ) -> Result<Vec<ApiKey>, AuthError> {
        let mut keys: Vec<_> = self
            .state
            .read()
            .await
            .api_keys
            .values()
            .filter(|api_key| {
                api_key.reference_id == reference_id && api_key.config_id == config_id
            })
            .cloned()
            .collect();
        keys.sort_by_key(|api_key| std::cmp::Reverse(api_key.created_at));
        Ok(keys)
    }

    async fn revoke_api_key(
        &self,
        reference_id: Uuid,
        api_key_id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        let mut state = self.state.write().await;
        let Some(api_key) = state
            .api_keys
            .get_mut(&api_key_id)
            .filter(|api_key| api_key.reference_id == reference_id)
        else {
            return Ok(false);
        };
        api_key.enabled = false;
        api_key.key_hash.clear();
        api_key.updated_at = revoked_at;
        Ok(true)
    }

    async fn record_api_key_use(
        &self,
        api_key_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<ApiKey>, AuthError> {
        let mut state = self.state.write().await;
        let Some(api_key) = state.api_keys.get_mut(&api_key_id) else {
            return Ok(None);
        };
        if !api_key.enabled || api_key.expires_at <= now {
            return Ok(None);
        }
        let reset = api_key.last_request.is_none_or(|last_request| {
            last_request + Duration::seconds(api_key.rate_limit_window_seconds) <= now
        });
        if api_key.rate_limit_enabled && !reset && api_key.request_count >= api_key.rate_limit_max {
            return Ok(None);
        }
        api_key.request_count = if reset {
            1
        } else {
            api_key.request_count.saturating_add(1)
        };
        api_key.last_request = Some(now);
        api_key.updated_at = now;
        Ok(Some(api_key.clone()))
    }
}
