use std::{collections::HashMap, sync::Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;

#[async_trait]
pub(crate) trait AgentJwtReplayStore: Send + Sync {
    async fn reserve(
        &self,
        key: String,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<bool, String>;
}

#[derive(Debug, Default)]
pub(crate) struct MemoryAgentJwtReplayStore {
    entries: Mutex<HashMap<String, DateTime<Utc>>>,
}

pub(crate) struct SecondaryAgentJwtReplayStore {
    storage: Arc<dyn crate::SecondaryStorage>,
}

impl SecondaryAgentJwtReplayStore {
    pub(crate) fn new(storage: Arc<dyn crate::SecondaryStorage>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl AgentJwtReplayStore for SecondaryAgentJwtReplayStore {
    async fn reserve(
        &self,
        key: String,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<bool, String> {
        let ttl = (expires_at - now)
            .num_seconds()
            .max(1)
            .try_into()
            .map_err(|_| "JTI replay TTL is too large".to_owned())?;
        self.storage
            .increment(&format!("agent-auth:jti:{key}"), Some(ttl))
            .await
            .map(|count| count == 1)
            .map_err(|error| error.to_string())
    }
}

#[async_trait]
impl AgentJwtReplayStore for MemoryAgentJwtReplayStore {
    async fn reserve(
        &self,
        key: String,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<bool, String> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| "JTI replay store lock failed".to_owned())?;
        entries.retain(|_, expiry| *expiry > now);
        if entries.contains_key(&key) {
            return Ok(false);
        }
        entries.insert(key, expires_at);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reservation_is_atomic_and_expired_entries_are_reusable() {
        let cache = MemoryAgentJwtReplayStore::default();
        let now = Utc::now();
        let expiry = now + chrono::Duration::minutes(1);
        assert!(
            cache
                .reserve("agent:jti".into(), expiry, now)
                .await
                .unwrap()
        );
        assert!(
            !cache
                .reserve("agent:jti".into(), expiry, now)
                .await
                .unwrap()
        );
        assert!(
            cache
                .reserve(
                    "agent:jti".into(),
                    expiry + chrono::Duration::minutes(1),
                    expiry,
                )
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn secondary_reservations_are_shared_across_verifier_instances() {
        let storage = Arc::new(crate::MemorySecondaryStorage::default());
        let first = SecondaryAgentJwtReplayStore::new(storage.clone());
        let second = SecondaryAgentJwtReplayStore::new(storage);
        let now = Utc::now();
        let expiry = now + chrono::Duration::minutes(1);
        assert!(
            first
                .reserve("agent:jti".into(), expiry, now)
                .await
                .unwrap()
        );
        assert!(
            !second
                .reserve("agent:jti".into(), expiry, now)
                .await
                .unwrap()
        );
    }
}
