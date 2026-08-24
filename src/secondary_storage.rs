use crate::AuthError;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

/// Better Auth secondary-storage contract.
///
/// Implementations must make `increment` atomic. TTL values are seconds and
/// `None` means the implementation's default/no-expiry behavior.
#[async_trait]
pub trait SecondaryStorage: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>, AuthError>;
    async fn get_and_delete(&self, key: &str) -> Result<Option<String>, AuthError>;
    async fn set(&self, key: &str, value: String, ttl: Option<u64>) -> Result<(), AuthError>;
    async fn delete(&self, key: &str) -> Result<(), AuthError>;
    async fn increment(&self, key: &str, ttl: Option<u64>) -> Result<u64, AuthError>;
}

#[derive(Clone, Default)]
pub struct MemorySecondaryStorage {
    entries: Arc<Mutex<HashMap<String, Entry>>>,
}

struct Entry {
    value: String,
    expires_at: Option<DateTime<Utc>>,
}

impl MemorySecondaryStorage {
    fn expiry(ttl: Option<u64>) -> Result<Option<DateTime<Utc>>, AuthError> {
        ttl.map(|seconds| {
            i64::try_from(seconds)
                .map(|seconds| Utc::now() + Duration::seconds(seconds))
                .map_err(|_| AuthError::Storage("secondary-storage TTL is too large".into()))
        })
        .transpose()
    }
}

#[async_trait]
impl SecondaryStorage for MemorySecondaryStorage {
    async fn get(&self, key: &str) -> Result<Option<String>, AuthError> {
        let mut entries = self.entries.lock().await;
        if entries
            .get(key)
            .and_then(|entry| entry.expires_at)
            .is_some_and(|expires| expires <= Utc::now())
        {
            entries.remove(key);
        }
        Ok(entries.get(key).map(|entry| entry.value.clone()))
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<String>, AuthError> {
        let mut entries = self.entries.lock().await;
        if entries
            .get(key)
            .and_then(|entry| entry.expires_at)
            .is_some_and(|expires| expires <= Utc::now())
        {
            entries.remove(key);
            return Ok(None);
        }
        Ok(entries.remove(key).map(|entry| entry.value))
    }

    async fn set(&self, key: &str, value: String, ttl: Option<u64>) -> Result<(), AuthError> {
        self.entries.lock().await.insert(
            key.into(),
            Entry {
                value,
                expires_at: Self::expiry(ttl)?,
            },
        );
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), AuthError> {
        self.entries.lock().await.remove(key);
        Ok(())
    }

    async fn increment(&self, key: &str, ttl: Option<u64>) -> Result<u64, AuthError> {
        let mut entries = self.entries.lock().await;
        let expired = entries
            .get(key)
            .and_then(|entry| entry.expires_at)
            .is_some_and(|expires| expires <= Utc::now());
        if expired {
            entries.remove(key);
        }
        let current = entries
            .get(key)
            .and_then(|entry| entry.value.parse::<u64>().ok())
            .unwrap_or(0)
            .saturating_add(1);
        let expires_at = entries
            .get(key)
            .and_then(|entry| entry.expires_at)
            .or(Self::expiry(ttl)?);
        entries.insert(
            key.into(),
            Entry {
                value: current.to_string(),
                expires_at,
            },
        );
        Ok(current)
    }
}
