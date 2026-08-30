use super::{NewSsoProvider, SsoProvider, SsoProviderUpdate, SsoStore, SsoStoreError};
use async_trait::async_trait;
use std::sync::Arc;

mod codec;
mod operations;

#[derive(Clone)]
pub struct DatabaseSsoStore {
    pub(super) store: Arc<dyn crate::AuthStore>,
}

impl DatabaseSsoStore {
    pub fn new(store: Arc<dyn crate::AuthStore>) -> Self {
        Self { store }
    }
}

impl std::fmt::Debug for DatabaseSsoStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DatabaseSsoStore")
            .field("adapter", &self.store.database_adapter_name())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SsoStore for DatabaseSsoStore {
    async fn create(&self, provider: NewSsoProvider) -> Result<SsoProvider, SsoStoreError> {
        operations::create(self, provider).await
    }

    async fn list(&self) -> Result<Vec<SsoProvider>, SsoStoreError> {
        operations::list(self).await
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<SsoProvider>, SsoStoreError> {
        operations::find(self, "id", id).await
    }

    async fn find_by_provider_id(
        &self,
        provider_id: &str,
    ) -> Result<Option<SsoProvider>, SsoStoreError> {
        operations::find(self, "providerId", provider_id).await
    }

    async fn update(
        &self,
        id: &str,
        update: SsoProviderUpdate,
    ) -> Result<SsoProvider, SsoStoreError> {
        operations::update(self, id, update).await
    }

    async fn delete(&self, id: &str) -> Result<Option<SsoProvider>, SsoStoreError> {
        operations::delete(self, id).await
    }
}
