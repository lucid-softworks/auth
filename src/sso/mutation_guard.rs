use crate::{AuthError, DatabaseTransaction};
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoMutationProvider {
    pub id: String,
    pub provider_id: String,
    pub organization_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsoProviderMutationGuardInput {
    Update {
        provider: SsoMutationProvider,
        provider_reference: super::SsoProviderReference,
        is_authentication_boundary_change: bool,
    },
    Delete {
        provider: SsoMutationProvider,
        provider_reference: super::SsoProviderReference,
    },
}

#[derive(Clone)]
pub struct SsoProviderMutationGuardContext {
    pub database: Arc<dyn DatabaseTransaction>,
}

impl std::fmt::Debug for SsoProviderMutationGuardContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SsoProviderMutationGuardContext")
            .finish_non_exhaustive()
    }
}

#[async_trait]
pub trait SsoProviderMutationGuard: Send + Sync {
    async fn guard(
        &self,
        input: SsoProviderMutationGuardInput,
        context: SsoProviderMutationGuardContext,
    ) -> Result<(), AuthError>;
}
