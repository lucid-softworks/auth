use super::InstrumentedAuthStore;
use crate::{
    ApiKey, ApiKeyStore, ApiKeyUseOutcome, AuthError, DatabaseCreate,
    instrumentation::{AdapterOperation, with_adapter_operation},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl ApiKeyStore for InstrumentedAuthStore {
    async fn create_api_key(&self, api_key: DatabaseCreate<ApiKey>) -> Result<ApiKey, AuthError> {
        with_adapter_operation(
            AdapterOperation::Create,
            "apikey",
            self.inner.create_api_key(api_key),
        )
        .await
    }

    async fn find_api_key(&self, api_key_id: &str) -> Result<Option<ApiKey>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindOne,
            "apikey",
            self.inner.find_api_key(api_key_id),
        )
        .await
    }

    async fn find_api_key_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindOne,
            "apikey",
            self.inner.find_api_key_by_hash(key_hash),
        )
        .await
    }

    async fn list_api_keys(
        &self,
        reference_id: &str,
        config_id: Option<&str>,
    ) -> Result<Vec<ApiKey>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindMany,
            "apikey",
            self.inner.list_api_keys(reference_id, config_id),
        )
        .await
    }

    async fn update_api_key(&self, api_key: ApiKey) -> Result<Option<ApiKey>, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "apikey",
            self.inner.update_api_key(api_key),
        )
        .await
    }

    async fn delete_api_key(&self, api_key_id: &str) -> Result<bool, AuthError> {
        with_adapter_operation(
            AdapterOperation::Delete,
            "apikey",
            self.inner.delete_api_key(api_key_id),
        )
        .await
    }

    async fn delete_expired_api_keys(&self, now: DateTime<Utc>) -> Result<u64, AuthError> {
        with_adapter_operation(
            AdapterOperation::DeleteMany,
            "apikey",
            self.inner.delete_expired_api_keys(now),
        )
        .await
    }

    async fn record_api_key_use(
        &self,
        api_key_id: &str,
        now: DateTime<Utc>,
        rate_limit_enabled: bool,
    ) -> Result<ApiKeyUseOutcome, AuthError> {
        with_adapter_operation(
            AdapterOperation::IncrementOne,
            "apikey",
            self.inner
                .record_api_key_use(api_key_id, now, rate_limit_enabled),
        )
        .await
    }
}
