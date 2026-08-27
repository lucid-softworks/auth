use super::{keys, record, reference_lock};
use crate::{ApiKey, AuthError, SecondaryStorage};
use chrono::Utc;
use std::sync::Arc;
use tokio::task::JoinSet;

const HYDRATION_CONCURRENCY: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeySecondaryStorageMode {
    SecondaryOnly,
    DatabaseFallback,
}

#[derive(Clone)]
pub struct ApiKeySecondaryStorage {
    storage: Arc<dyn SecondaryStorage>,
    mode: ApiKeySecondaryStorageMode,
}

impl ApiKeySecondaryStorage {
    pub fn new(storage: Arc<dyn SecondaryStorage>, mode: ApiKeySecondaryStorageMode) -> Self {
        Self { storage, mode }
    }

    pub async fn get_by_hash(&self, hashed_key: &str) -> Result<Option<ApiKey>, AuthError> {
        self.get(&keys::by_hash(hashed_key)).await
    }

    pub async fn get_by_id(&self, id: &str) -> Result<Option<ApiKey>, AuthError> {
        self.get(&keys::by_id(id)).await
    }

    pub async fn set(&self, api_key: &ApiKey) -> Result<(), AuthError> {
        let value = record::serialize(api_key)?;
        let ttl = record::ttl_at(api_key.expires_at, Utc::now());
        self.storage
            .set(&keys::by_hash(&api_key.key_hash), value.clone(), ttl)
            .await?;
        self.storage
            .set(&keys::by_id(&api_key.id), value, ttl)
            .await?;
        match self.mode {
            ApiKeySecondaryStorageMode::SecondaryOnly => {
                self.mutate_reference_ids(&api_key.reference_id, |ids| {
                    if !ids.iter().any(|id| id == &api_key.id) {
                        ids.push(api_key.id.clone());
                    }
                })
                .await
            }
            ApiKeySecondaryStorageMode::DatabaseFallback => {
                self.storage
                    .delete(&keys::by_reference(&api_key.reference_id))
                    .await
            }
        }
    }

    pub async fn delete(&self, api_key: &ApiKey) -> Result<(), AuthError> {
        self.storage
            .delete(&keys::by_hash(&api_key.key_hash))
            .await?;
        self.storage.delete(&keys::by_id(&api_key.id)).await?;
        match self.mode {
            ApiKeySecondaryStorageMode::SecondaryOnly => {
                self.mutate_reference_ids(&api_key.reference_id, |ids| {
                    ids.retain(|id| id != &api_key.id);
                })
                .await
            }
            ApiKeySecondaryStorageMode::DatabaseFallback => {
                self.storage
                    .delete(&keys::by_reference(&api_key.reference_id))
                    .await
            }
        }
    }

    pub async fn reference_ids(&self, reference_id: &str) -> Result<Vec<String>, AuthError> {
        let raw = self.storage.get(&keys::by_reference(reference_id)).await?;
        Ok(keys::parse_reference_ids(raw.as_deref()))
    }

    pub async fn cache_reference_ids(
        &self,
        reference_id: &str,
        ids: &[String],
    ) -> Result<(), AuthError> {
        let key = keys::by_reference(reference_id);
        if ids.is_empty() {
            self.storage.delete(&key).await
        } else {
            self.storage
                .set(&key, keys::serialize_reference_ids(ids), None)
                .await
        }
    }

    pub async fn list_by_reference(&self, reference_id: &str) -> Result<Vec<ApiKey>, AuthError> {
        let ids = self.reference_ids(reference_id).await?;
        let mut records = vec![None; ids.len()];
        for (offset, ids) in ids.chunks(HYDRATION_CONCURRENCY).enumerate() {
            let mut tasks = JoinSet::new();
            for (index, id) in ids.iter().cloned().enumerate() {
                let storage = self.clone();
                tasks.spawn(async move { (index, storage.get_by_id(&id).await) });
            }
            while let Some(result) = tasks.join_next().await {
                let (index, record) = result.map_err(|_| AuthError::Worker)?;
                records[offset * HYDRATION_CONCURRENCY + index] = record?;
            }
        }
        Ok(records.into_iter().flatten().collect())
    }

    async fn get(&self, key: &str) -> Result<Option<ApiKey>, AuthError> {
        let raw = self.storage.get(key).await?;
        Ok(record::deserialize(raw.as_deref()))
    }

    async fn mutate_reference_ids(
        &self,
        reference_id: &str,
        mutate: impl FnOnce(&mut Vec<String>),
    ) -> Result<(), AuthError> {
        let key = keys::by_reference(reference_id);
        let _guard = reference_lock::acquire(&key).await;
        let raw = self.storage.get(&key).await?;
        let mut ids = keys::parse_reference_ids(raw.as_deref());
        mutate(&mut ids);
        if ids.is_empty() {
            self.storage.delete(&key).await
        } else {
            self.storage
                .set(&key, keys::serialize_reference_ids(&ids), None)
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chrono::{Duration, Timelike};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn gets_sets_and_deletes_secondary_only_records() {
        let storage = Arc::new(crate::MemorySecondaryStorage::default());
        let adapter =
            ApiKeySecondaryStorage::new(storage.clone(), ApiKeySecondaryStorageMode::SecondaryOnly);
        let first = fixture(1);
        let second = fixture(2);

        adapter.set(&first).await.unwrap();
        adapter.set(&first).await.unwrap();
        adapter.set(&second).await.unwrap();
        assert_eq!(
            adapter.get_by_hash("hash-1").await.unwrap(),
            Some(first.clone())
        );
        assert_eq!(
            adapter.get_by_id("key-2").await.unwrap(),
            Some(second.clone())
        );
        assert_eq!(
            adapter.reference_ids("user-id").await.unwrap(),
            vec!["key-1", "key-2"]
        );

        adapter.delete(&first).await.unwrap();
        assert_eq!(adapter.get_by_hash("hash-1").await.unwrap(), None);
        assert_eq!(
            adapter.reference_ids("user-id").await.unwrap(),
            vec!["key-2"]
        );
        adapter.delete(&second).await.unwrap();
        assert_eq!(
            adapter.reference_ids("user-id").await.unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(storage.get("api-key:by-ref:user-id").await.unwrap(), None);
    }

    #[tokio::test]
    async fn fallback_mode_invalidates_reference_lists() {
        let storage = Arc::new(crate::MemorySecondaryStorage::default());
        let adapter = ApiKeySecondaryStorage::new(
            storage.clone(),
            ApiKeySecondaryStorageMode::DatabaseFallback,
        );
        storage
            .set("api-key:by-ref:user-id", r#"["stale"]"#.into(), None)
            .await
            .unwrap();
        let api_key = fixture(1);
        adapter.set(&api_key).await.unwrap();
        assert_eq!(storage.get("api-key:by-ref:user-id").await.unwrap(), None);
        assert!(storage.get("api-key:hash-1").await.unwrap().is_some());
        assert!(storage.get("api-key:by-id:key-1").await.unwrap().is_some());

        storage
            .set("api-key:by-ref:user-id", r#"["stale"]"#.into(), None)
            .await
            .unwrap();
        adapter.delete(&api_key).await.unwrap();
        assert_eq!(storage.get("api-key:hash-1").await.unwrap(), None);
        assert_eq!(storage.get("api-key:by-id:key-1").await.unwrap(), None);
        assert_eq!(storage.get("api-key:by-ref:user-id").await.unwrap(), None);
    }

    #[tokio::test]
    async fn concurrent_reference_mutations_do_not_lose_ids() {
        let storage = Arc::new(crate::MemorySecondaryStorage::default());
        let adapter =
            ApiKeySecondaryStorage::new(storage, ApiKeySecondaryStorageMode::SecondaryOnly);
        let mut tasks = JoinSet::new();
        for number in 0..32 {
            let adapter = adapter.clone();
            tasks.spawn(async move { adapter.set(&fixture(number)).await });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        let mut ids = adapter.reference_ids("user-id").await.unwrap();
        ids.sort();
        let mut expected = (0..32)
            .map(|number| format!("key-{number}"))
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[tokio::test]
    async fn hydrates_at_most_ten_records_concurrently_and_preserves_order() {
        let storage = Arc::new(ConcurrencyStorage::default());
        let adapter =
            ApiKeySecondaryStorage::new(storage.clone(), ApiKeySecondaryStorageMode::SecondaryOnly);
        for number in 0..25 {
            adapter.set(&fixture(number)).await.unwrap();
        }
        storage.track_reads.store(true, Ordering::SeqCst);

        let records = adapter.list_by_reference("user-id").await.unwrap();
        assert_eq!(records.len(), 25);
        assert_eq!(records[0].id, "key-0");
        assert_eq!(records[24].id, "key-24");
        assert!(storage.maximum.load(Ordering::SeqCst) > 1);
        assert!(storage.maximum.load(Ordering::SeqCst) <= HYDRATION_CONCURRENCY);
    }

    #[derive(Default)]
    struct ConcurrencyStorage {
        inner: crate::MemorySecondaryStorage,
        active: AtomicUsize,
        maximum: AtomicUsize,
        track_reads: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl SecondaryStorage for ConcurrencyStorage {
        async fn get(&self, key: &str) -> Result<Option<String>, AuthError> {
            if !self.track_reads.load(Ordering::SeqCst) || !key.starts_with("api-key:by-id:") {
                return self.inner.get(key).await;
            }
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let result = self.inner.get(key).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            result
        }

        async fn get_and_delete(&self, key: &str) -> Result<Option<String>, AuthError> {
            self.inner.get_and_delete(key).await
        }

        async fn set(&self, key: &str, value: String, ttl: Option<u64>) -> Result<(), AuthError> {
            self.inner.set(key, value, ttl).await
        }

        async fn delete(&self, key: &str) -> Result<(), AuthError> {
            self.inner.delete(key).await
        }

        async fn increment(&self, key: &str, ttl: Option<u64>) -> Result<u64, AuthError> {
            self.inner.increment(key, ttl).await
        }
    }

    fn fixture(number: usize) -> ApiKey {
        let now = Utc::now();
        let created_at = now
            .with_nanosecond(now.nanosecond() / 1_000_000 * 1_000_000)
            .unwrap();
        ApiKey {
            id: format!("key-{number}"),
            config_id: "default".into(),
            name: None,
            start: None,
            prefix: None,
            key_hash: format!("hash-{number}"),
            reference_id: "user-id".into(),
            refill_interval: None,
            refill_amount: None,
            last_refill_at: None,
            enabled: true,
            rate_limit_enabled: true,
            rate_limit_time_window: Some(86_400_000),
            rate_limit_max: Some(10),
            request_count: 0,
            remaining: None,
            last_request: None,
            expires_at: Some(created_at + Duration::hours(1)),
            permissions: None,
            metadata: None,
            created_at,
            updated_at: created_at,
        }
    }
}
