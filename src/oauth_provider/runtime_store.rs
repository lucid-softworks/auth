use super::{OAuthProviderClient, OAuthProviderConfig, OAuthProviderResource, OAuthProviderStore};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, RwLock};

mod client;
mod passthrough;
mod resource;
pub(super) mod seed;

pub(super) struct OAuthProviderRuntimeStore {
    pub(super) config: Arc<OAuthProviderConfig>,
    pub(super) inner: Arc<dyn OAuthProviderStore>,
    pub(super) client_cache: RwLock<HashMap<String, OAuthProviderClient>>,
    pub(super) resource_cache: RwLock<HashMap<String, OAuthProviderResource>>,
    pub(super) seed_lock: Mutex<()>,
    pub(super) seed_complete: std::sync::atomic::AtomicBool,
}

impl OAuthProviderRuntimeStore {
    pub(super) fn new(
        config: Arc<OAuthProviderConfig>,
        inner: Arc<dyn OAuthProviderStore>,
    ) -> Self {
        Self {
            config,
            inner,
            client_cache: RwLock::new(HashMap::new()),
            resource_cache: RwLock::new(HashMap::new()),
            seed_lock: Mutex::new(()),
            seed_complete: std::sync::atomic::AtomicBool::new(false),
        }
    }
}
