use super::DashAuthorizationError;
use crate::infra::dash::{DashApiClient, DashRequest};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::OnceLock,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, watch};

const CACHE_TTL: Duration = Duration::from_millis(900_000);
type FetchResult = Result<Value, DashAuthorizationError>;

#[derive(Clone)]
struct CachedJwks {
    data: Value,
    expires_at: Instant,
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<String, CachedJwks>,
    inflight: HashMap<String, watch::Receiver<Option<FetchResult>>>,
}

fn state() -> &'static Mutex<CacheState> {
    static STATE: OnceLock<Mutex<CacheState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(CacheState::default()))
}

pub(super) async fn get(
    cache_key: &str,
    api: &DashApiClient,
) -> Result<Value, DashAuthorizationError> {
    enum Plan {
        Return(Value),
        Wait(watch::Receiver<Option<FetchResult>>),
        Fetch(watch::Sender<Option<FetchResult>>),
    }

    let plan = {
        let mut state = state().lock().await;
        if let Some(cached) = state.entries.get(cache_key).cloned() {
            if Instant::now() < cached.expires_at {
                Plan::Return(cached.data)
            } else {
                if !state.inflight.contains_key(cache_key) {
                    let (sender, receiver) = watch::channel(None);
                    state.inflight.insert(cache_key.to_owned(), receiver);
                    let cache_key = cache_key.to_owned();
                    let api = api.clone();
                    tokio::spawn(async move {
                        let result = fetch_and_store(&cache_key, &api).await;
                        let _ = sender.send(Some(result));
                    });
                }
                Plan::Return(cached.data)
            }
        } else if let Some(receiver) = state.inflight.get(cache_key) {
            Plan::Wait(receiver.clone())
        } else {
            let (sender, receiver) = watch::channel(None);
            state.inflight.insert(cache_key.to_owned(), receiver);
            Plan::Fetch(sender)
        }
    };

    match plan {
        Plan::Return(data) => Ok(data),
        Plan::Wait(mut receiver) => wait_for_result(&mut receiver).await,
        Plan::Fetch(sender) => {
            let result = fetch_and_store(cache_key, api).await;
            let _ = sender.send(Some(result.clone()));
            result
        }
    }
}

async fn wait_for_result(
    receiver: &mut watch::Receiver<Option<FetchResult>>,
) -> Result<Value, DashAuthorizationError> {
    loop {
        if let Some(result) = receiver.borrow().clone() {
            return result;
        }
        receiver
            .changed()
            .await
            .map_err(|_| DashAuthorizationError)?;
    }
}

async fn fetch_and_store(
    cache_key: &str,
    api: &DashApiClient,
) -> Result<Value, DashAuthorizationError> {
    let result = fetch(api).await;
    let mut state = state().lock().await;
    if let Ok(data) = &result {
        state.entries.insert(
            cache_key.to_owned(),
            CachedJwks {
                data: data.clone(),
                expires_at: Instant::now() + CACHE_TTL,
            },
        );
    }
    state.inflight.remove(cache_key);
    result
}

async fn fetch(api: &DashApiClient) -> Result<Value, DashAuthorizationError> {
    let response = api
        .execute(DashRequest::get("/api/auth/jwks"))
        .await
        .map_err(|_| DashAuthorizationError)?;
    let data = response
        .data
        .filter(js_truthy)
        .filter(|_| response.error.is_none())
        .ok_or(DashAuthorizationError)?;
    Ok(data)
}

fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

#[cfg(all(test, feature = "axum"))]
pub(super) async fn seed(cache_key: &str, data: Value, expires_at: Instant) {
    state()
        .lock()
        .await
        .entries
        .insert(cache_key.to_owned(), CachedJwks { data, expires_at });
}
