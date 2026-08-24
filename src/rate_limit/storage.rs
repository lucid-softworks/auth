use super::{
    RateLimitConfig, RateLimitOutcome, RateLimitRule, RateLimitStorage, RateLimitStorageMode,
};
use crate::{AuthError, AuthStore, PluginRateLimit};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::Mutex;

pub(crate) enum RateLimiter {
    Memory(MemoryRateLimitStorage),
    Database {
        store: Arc<dyn AuthStore>,
        longest_window: AtomicU64,
    },
    External(Arc<dyn RateLimitStorage>),
}

impl RateLimiter {
    pub(crate) fn new(
        config: &RateLimitConfig,
        store: Arc<dyn AuthStore>,
        plugin_rules: &[PluginRateLimit],
    ) -> Self {
        match &config.storage {
            RateLimitStorageMode::Memory => Self::Memory(MemoryRateLimitStorage::default()),
            RateLimitStorageMode::Database => Self::Database {
                store,
                longest_window: AtomicU64::new(config.longest_window(plugin_rules)),
            },
            RateLimitStorageMode::SecondaryStorage(storage)
            | RateLimitStorageMode::Custom(storage) => Self::External(storage.clone()),
        }
    }

    pub(crate) async fn consume(
        &self,
        key: &str,
        rule: RateLimitRule,
    ) -> Result<RateLimitOutcome, AuthError> {
        match self {
            Self::Memory(storage) => storage.consume(key, rule).await,
            Self::Database {
                store,
                longest_window,
            } => {
                longest_window.fetch_max(rule.window, Ordering::Relaxed);
                store
                    .consume_rate_limit(
                        key,
                        Utc::now(),
                        rule,
                        longest_window.load(Ordering::Relaxed),
                    )
                    .await
            }
            Self::External(storage) => storage.consume(key, rule).await,
        }
    }
}

#[derive(Default)]
pub(crate) struct MemoryRateLimitStorage {
    entries: Mutex<HashMap<String, MemoryEntry>>,
}

struct MemoryEntry {
    count: u32,
    last_request: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[async_trait]
impl RateLimitStorage for MemoryRateLimitStorage {
    async fn consume(&self, key: &str, rule: RateLimitRule) -> Result<RateLimitOutcome, AuthError> {
        let now = Utc::now();
        let window = duration(rule.window)?;
        let mut entries = self.entries.lock().await;
        entries.retain(|_, entry| entry.expires_at > now);
        let Some(entry) = entries.get_mut(key) else {
            entries.insert(
                key.to_owned(),
                MemoryEntry {
                    count: 1,
                    last_request: now,
                    expires_at: now + window,
                },
            );
            return Ok(RateLimitOutcome::allowed());
        };
        if now - entry.last_request >= window {
            entry.count = 1;
            entry.last_request = now;
            entry.expires_at = now + window;
            return Ok(RateLimitOutcome::allowed());
        }
        if entry.count >= rule.max {
            return Ok(RateLimitOutcome::denied(retry_after(
                entry.last_request,
                window,
                now,
            )));
        }
        entry.count += 1;
        entry.last_request = now;
        entry.expires_at = now + window;
        Ok(RateLimitOutcome::allowed())
    }
}

pub(crate) fn duration(seconds: u64) -> Result<Duration, AuthError> {
    i64::try_from(seconds)
        .ok()
        .map(Duration::seconds)
        .ok_or_else(|| AuthError::InvalidConfiguration("rate-limit window is too large".into()))
}

pub(crate) fn retry_after(
    last_request: DateTime<Utc>,
    window: Duration,
    now: DateTime<Utc>,
) -> u64 {
    let remaining = (last_request + window - now).num_milliseconds();
    u64::try_from((remaining.max(0) + 999) / 1_000).unwrap_or(u64::MAX)
}
