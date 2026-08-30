use super::CimdOptions;
use indexmap::IndexMap;
use std::collections::VecDeque;

const WINDOW_MS: i64 = 60_000;

#[derive(Debug, Default)]
pub(super) struct FetchGovernor {
    active: usize,
    global_starts: VecDeque<i64>,
    client_starts: IndexMap<String, i64>,
    origins: IndexMap<String, OriginState>,
}

#[derive(Debug, Default)]
struct OriginState {
    active: usize,
    starts: VecDeque<i64>,
}

impl FetchGovernor {
    pub fn acquire(
        &mut self,
        client_id: &str,
        options: &CimdOptions,
        now_ms: i64,
    ) -> Result<String, String> {
        let minimum_ms = options.minimum_fetch_interval().as_millis() as i64;
        if minimum_ms > 0
            && self
                .client_starts
                .get(client_id)
                .is_some_and(|last| now_ms.saturating_sub(*last) < minimum_ms)
        {
            return Err("metadata document fetch is within the per-client minimum interval".into());
        }
        self.ensure_client_capacity(client_id, options.max_cache_entries, minimum_ms, now_ms)?;
        let origin = url::Url::parse(client_id)
            .map_err(|_| "client_id is not a valid URL".to_owned())?
            .origin()
            .ascii_serialization();
        self.prune(now_ms);
        self.ensure_origin_capacity(&origin, options.max_cache_entries)?;
        let policy = &options.metadata_fetch_policy;
        let origin_state = self.origins.get(&origin).expect("origin state exists");
        if self.active >= policy.maximum_concurrent_fetches {
            return Err("global metadata fetch concurrency limit exceeded".into());
        }
        if origin_state.active >= policy.maximum_concurrent_fetches_per_origin {
            return Err("metadata fetch concurrency limit exceeded for client origin".into());
        }
        if self.global_starts.len() >= policy.maximum_fetches_per_minute {
            return Err("global metadata fetch rate limit exceeded".into());
        }
        if origin_state.starts.len() >= policy.maximum_fetches_per_origin_per_minute {
            return Err("metadata fetch rate limit exceeded for client origin".into());
        }
        self.client_starts.shift_remove(client_id);
        self.client_starts.insert(client_id.into(), now_ms);
        self.global_starts.push_back(now_ms);
        self.active += 1;
        let origin_state = self.origins.get_mut(&origin).expect("origin state exists");
        origin_state.starts.push_back(now_ms);
        origin_state.active += 1;
        Ok(origin)
    }

    pub fn release(&mut self, origin: &str) {
        self.active = self.active.saturating_sub(1);
        if let Some(state) = self.origins.get_mut(origin) {
            state.active = state.active.saturating_sub(1);
        }
    }

    fn prune(&mut self, now_ms: i64) {
        prune_times(&mut self.global_starts, now_ms);
        for state in self.origins.values_mut() {
            prune_times(&mut state.starts, now_ms);
        }
    }

    fn ensure_client_capacity(
        &mut self,
        client_id: &str,
        maximum: usize,
        minimum_ms: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        if self.client_starts.contains_key(client_id) {
            return Ok(());
        }
        while self.client_starts.len() >= maximum {
            let evict = self
                .client_starts
                .iter()
                .find(|(_, last)| minimum_ms == 0 || now_ms.saturating_sub(**last) >= minimum_ms)
                .map(|(client_id, _)| client_id.clone());
            let Some(evict) = evict else {
                return Err("metadata fetch client state is at capacity".into());
            };
            self.client_starts.shift_remove(&evict);
        }
        Ok(())
    }

    fn ensure_origin_capacity(&mut self, origin: &str, maximum: usize) -> Result<(), String> {
        if self.origins.contains_key(origin) {
            let state = self.origins.shift_remove(origin).expect("origin exists");
            self.origins.insert(origin.into(), state);
            return Ok(());
        }
        while self.origins.len() >= maximum {
            let evict = self
                .origins
                .iter()
                .find(|(_, state)| state.active == 0 && state.starts.is_empty())
                .map(|(origin, _)| origin.clone());
            let Some(evict) = evict else {
                return Err("metadata fetch origin state is at capacity".into());
            };
            self.origins.shift_remove(&evict);
        }
        self.origins.insert(origin.into(), OriginState::default());
        Ok(())
    }
}

fn prune_times(times: &mut VecDeque<i64>, now_ms: i64) {
    let start = now_ms.saturating_sub(WINDOW_MS);
    while times.front().is_some_and(|value| *value <= start) {
        times.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CimdFetchError, CimdFetchRequest, CimdFetchResponse, CimdMetadataResourceFetcher};
    use async_trait::async_trait;
    use std::sync::Arc;

    struct Fetcher;
    #[async_trait]
    impl CimdMetadataResourceFetcher for Fetcher {
        async fn fetch(&self, _: CimdFetchRequest) -> Result<CimdFetchResponse, CimdFetchError> {
            unreachable!()
        }
    }

    #[test]
    fn pacing_and_concurrency_reject_without_queueing() {
        let mut options = CimdOptions::new(Arc::new(Fetcher));
        options.metadata_fetch_policy.maximum_concurrent_fetches = 1;
        let mut governor = FetchGovernor::default();
        let origin = governor.acquire("https://a.example/doc", &options, 1_000).unwrap();
        assert_eq!(
            governor.acquire("https://b.example/doc", &options, 1_000).unwrap_err(),
            "global metadata fetch concurrency limit exceeded"
        );
        governor.release(&origin);
        assert_eq!(
            governor.acquire("https://a.example/doc", &options, 1_500).unwrap_err(),
            "metadata document fetch is within the per-client minimum interval"
        );
    }

    #[test]
    fn per_origin_concurrency_and_rolling_budgets_are_independent() {
        let mut options = CimdOptions::new(Arc::new(Fetcher));
        options.metadata_fetch_policy.minimum_fetch_interval = 0_u64.into();
        options.metadata_fetch_policy.maximum_concurrent_fetches = 3;
        options.metadata_fetch_policy.maximum_concurrent_fetches_per_origin = 1;
        options.metadata_fetch_policy.maximum_fetches_per_minute = 2;
        options.metadata_fetch_policy.maximum_fetches_per_origin_per_minute = 1;
        let mut governor = FetchGovernor::default();

        let first = governor
            .acquire("https://a.example/one", &options, 1_000)
            .unwrap();
        assert_eq!(
            governor
                .acquire("https://a.example/two", &options, 1_000)
                .unwrap_err(),
            "metadata fetch concurrency limit exceeded for client origin"
        );
        governor.release(&first);
        assert_eq!(
            governor
                .acquire("https://a.example/two", &options, 1_001)
                .unwrap_err(),
            "metadata fetch rate limit exceeded for client origin"
        );
        let second = governor
            .acquire("https://b.example/one", &options, 1_001)
            .unwrap();
        governor.release(&second);
        assert_eq!(
            governor
                .acquire("https://c.example/one", &options, 1_002)
                .unwrap_err(),
            "global metadata fetch rate limit exceeded"
        );
        assert!(
            governor
                .acquire("https://a.example/two", &options, 61_001)
                .is_ok()
        );
    }

    #[test]
    fn bounded_state_evicts_only_records_outside_active_windows() {
        let mut options = CimdOptions::new(Arc::new(Fetcher));
        options.max_cache_entries = 1;
        options.metadata_fetch_policy.minimum_fetch_interval = 60_u64.into();
        let mut governor = FetchGovernor::default();
        let origin = governor
            .acquire("https://a.example/one", &options, 1_000)
            .unwrap();
        governor.release(&origin);
        assert_eq!(
            governor
                .acquire("https://b.example/one", &options, 1_001)
                .unwrap_err(),
            "metadata fetch client state is at capacity"
        );
        assert!(
            governor
                .acquire("https://b.example/one", &options, 61_001)
                .is_ok()
        );
    }
}
