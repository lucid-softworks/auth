use crate::AuthStore;
use std::sync::Arc;

macro_rules! delegate_store_metadata {
    () => {
        fn database_adapter_name(&self) -> &str {
            self.inner.database_adapter_name()
        }

        fn database_id_capabilities(&self) -> crate::DatabaseIdAdapterCapabilities {
            self.inner.database_id_capabilities()
        }

        fn database_id_generator(&self) -> Option<&dyn crate::DatabaseIdGenerator> {
            self.inner.database_id_generator()
        }

        fn bind_schema(
            &self,
            schema: std::sync::Arc<crate::AuthSchemaCatalog>,
        ) -> Result<(), crate::AuthError> {
            self.inner.bind_schema(schema)
        }

        fn jwk_store(&self) -> Option<&dyn crate::JwkStore> {
            self.inner.jwk_store()
        }
    };
}

mod access;
mod api_key;
mod auth;
mod oauth;
mod security;
mod verification;

pub(crate) struct InstrumentedAuthStore {
    pub(super) inner: Arc<dyn AuthStore>,
}

impl InstrumentedAuthStore {
    pub(crate) fn new(inner: Arc<dyn AuthStore>) -> Self {
        Self { inner }
    }
}
