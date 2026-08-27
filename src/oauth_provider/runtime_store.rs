use super::{OAuthProviderClient, OAuthProviderConfig, OAuthProviderResource, OAuthProviderStore};
use crate::{AuthError, AuthStore, DatabaseIdGeneration, DatabaseIdInput, DatabaseIdPlan};
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};
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
    database_ids: OnceLock<DatabaseIds>,
}

struct DatabaseIds {
    strategy: DatabaseIdGeneration,
    store: Arc<dyn AuthStore>,
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
            database_ids: OnceLock::new(),
        }
    }

    pub(super) fn bind_database_ids(
        &self,
        store: Arc<dyn AuthStore>,
        strategy: DatabaseIdGeneration,
    ) -> Result<(), AuthError> {
        self.database_ids
            .set(DatabaseIds { strategy, store })
            .map_err(|_| {
                AuthError::InvalidConfiguration(
                    "OAuth Provider store is already bound to an auth service".into(),
                )
            })
    }

    pub(super) fn prepare_id(
        &self,
        model: &'static str,
    ) -> Result<crate::PreparedDatabaseId, AuthError> {
        let ids = self.database_ids.get().ok_or_else(|| {
            AuthError::InvalidConfiguration(
                "OAuth Provider store must be bound through AuthService before use".into(),
            )
        })?;
        DatabaseIdPlan::new(ids.strategy.clone(), model, DatabaseIdInput::Absent, false)
            .prepare(ids.store.as_ref())
    }
}
