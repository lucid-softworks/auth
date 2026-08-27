use crate::infra::dash::{DashKvClient, DashRequest, ResolvedKvRetryOptions};
use reqwest::StatusCode;
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::OnceLock,
    time::{Duration, Instant},
};
use tokio::{sync::Mutex, time::sleep};

const CACHE_TTL: Duration = Duration::from_millis(60_000);
const CACHE_MAX_SIZE: usize = 1_000;

#[derive(Clone)]
struct CacheEntry {
    data: Option<Value>,
    timestamp: Instant,
}

struct CacheState {
    entries: HashMap<String, CacheEntry>,
    last_cleanup: Instant,
}

impl Default for CacheState {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }
}

fn state() -> &'static Mutex<CacheState> {
    static STATE: OnceLock<Mutex<CacheState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(CacheState::default()))
}

pub(super) async fn get(
    request_id: &str,
    kv: &DashKvClient,
    retry: ResolvedKvRetryOptions,
) -> Option<Value> {
    if let Some(cached) = cached(request_id).await {
        return cached;
    }
    for attempt in 0..=retry.attempts {
        match kv
            .execute(DashRequest::get(format!("/identify/{request_id}")))
            .await
        {
            Ok(response) if response.error.is_none() => {
                if let Some(data) = response.data {
                    insert(request_id, Some(data.clone())).await;
                    return Some(data);
                }
                insert(request_id, None).await;
                return None;
            }
            Ok(response) if response.status != StatusCode::NOT_FOUND => {
                insert(request_id, None).await;
                return None;
            }
            Ok(_) | Err(_) if attempt < retry.attempts => {
                sleep(retry_delay(retry, attempt)).await;
            }
            Ok(_) | Err(_) => return None,
        }
    }
    None
}

async fn cached(request_id: &str) -> Option<Option<Value>> {
    let mut state = state().lock().await;
    let now = Instant::now();
    maybe_cleanup(&mut state, now);
    state
        .entries
        .get(request_id)
        .filter(|entry| now.duration_since(entry.timestamp) < CACHE_TTL)
        .map(|entry| entry.data.clone())
}

fn maybe_cleanup(state: &mut CacheState, now: Instant) {
    if now.duration_since(state.last_cleanup) > CACHE_TTL || state.entries.len() > CACHE_MAX_SIZE {
        state
            .entries
            .retain(|_, entry| now.duration_since(entry.timestamp) <= CACHE_TTL);
        state.last_cleanup = now;
    }
}

async fn insert(request_id: &str, data: Option<Value>) {
    state().lock().await.entries.insert(
        request_id.to_owned(),
        CacheEntry {
            data,
            timestamp: Instant::now(),
        },
    );
}

fn retry_delay(retry: ResolvedKvRetryOptions, attempt: u32) -> Duration {
    retry
        .base_delay
        .saturating_mul(2_u32.saturating_pow(attempt))
        .min(retry.max_delay)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_clock_pins_ttl_and_cleanup_threshold_boundaries() {
        let now = Instant::now();
        let mut cache = CacheState {
            entries: HashMap::from([
                (
                    "fresh".into(),
                    CacheEntry {
                        data: Some(Value::Bool(true)),
                        timestamp: now - CACHE_TTL + Duration::from_millis(1),
                    },
                ),
                (
                    "boundary".into(),
                    CacheEntry {
                        data: None,
                        timestamp: now - CACHE_TTL,
                    },
                ),
                (
                    "expired".into(),
                    CacheEntry {
                        data: None,
                        timestamp: now - CACHE_TTL - Duration::from_millis(1),
                    },
                ),
            ]),
            last_cleanup: now - CACHE_TTL - Duration::from_millis(1),
        };
        maybe_cleanup(&mut cache, now);
        assert!(cache.entries.contains_key("fresh"));
        assert!(cache.entries.contains_key("boundary"));
        assert!(!cache.entries.contains_key("expired"));

        cache.last_cleanup = now - Duration::from_millis(1);
        cache.entries.extend((0..=CACHE_MAX_SIZE).map(|index| {
            (
                format!("entry-{index}"),
                CacheEntry {
                    data: None,
                    timestamp: now,
                },
            )
        }));
        maybe_cleanup(&mut cache, now);
        assert_eq!(cache.last_cleanup, now);
        assert!(cache.entries.len() > CACHE_MAX_SIZE);
    }
}
