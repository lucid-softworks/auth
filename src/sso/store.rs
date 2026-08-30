use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoProvider {
    pub id: String,
    pub issuer: String,
    pub oidc_config: Option<Value>,
    pub saml_config: Option<Value>,
    pub user_id: String,
    pub provider_id: String,
    pub organization_id: Option<String>,
    pub domain: String,
    pub domain_verified: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewSsoProvider {
    pub id: String,
    pub issuer: String,
    pub oidc_config: Option<Value>,
    pub saml_config: Option<Value>,
    pub user_id: String,
    pub provider_id: String,
    pub organization_id: Option<String>,
    pub domain: String,
    pub domain_verified: Option<bool>,
}

impl NewSsoProvider {
    pub fn into_provider(self) -> SsoProvider {
        SsoProvider {
            id: self.id,
            issuer: self.issuer,
            oidc_config: self.oidc_config,
            saml_config: self.saml_config,
            user_id: self.user_id,
            provider_id: self.provider_id,
            organization_id: self.organization_id,
            domain: self.domain,
            domain_verified: self.domain_verified,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SsoProviderUpdate {
    pub issuer: Option<String>,
    pub oidc_config: Option<Option<Value>>,
    pub saml_config: Option<Option<Value>>,
    pub provider_id: Option<String>,
    pub organization_id: Option<Option<String>>,
    pub domain: Option<String>,
    pub domain_verified: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SsoStoreError {
    #[error("SSO provider not found")]
    NotFound,
    #[error("SSO provider ID already exists")]
    DuplicateProviderId,
    #[error("linked SSO accounts prevent this identity-boundary change")]
    LinkedAccounts,
    #[error("SSO storage failed: {0}")]
    Storage(String),
}

#[async_trait]
pub trait SsoStore: Send + Sync {
    async fn create(&self, provider: NewSsoProvider) -> Result<SsoProvider, SsoStoreError>;
    async fn list(&self) -> Result<Vec<SsoProvider>, SsoStoreError>;
    async fn find_by_id(&self, id: &str) -> Result<Option<SsoProvider>, SsoStoreError>;
    async fn find_by_provider_id(
        &self,
        provider_id: &str,
    ) -> Result<Option<SsoProvider>, SsoStoreError>;
    async fn update(
        &self,
        id: &str,
        update: SsoProviderUpdate,
    ) -> Result<SsoProvider, SsoStoreError>;
    async fn delete(&self, id: &str) -> Result<Option<SsoProvider>, SsoStoreError>;
    async fn update_guarded(
        &self,
        id: &str,
        provider_id: &str,
        update: SsoProviderUpdate,
        identity_boundary_changed: bool,
    ) -> Result<SsoProvider, SsoStoreError> {
        let _ = (provider_id, identity_boundary_changed);
        self.update(id, update).await
    }
    async fn delete_with_accounts(
        &self,
        id: &str,
        provider_id: &str,
    ) -> Result<bool, SsoStoreError> {
        let _ = provider_id;
        self.delete(id).await.map(|provider| provider.is_some())
    }
    async fn verify_domain(
        &self,
        id: &str,
        expected_domain: &str,
    ) -> Result<bool, SsoStoreError>;
}

#[derive(Default)]
pub struct MemorySsoStore {
    providers: Mutex<BTreeMap<String, SsoProvider>>,
}

impl std::fmt::Debug for MemorySsoStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MemorySsoStore(..)")
    }
}

impl MemorySsoStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SsoStore for MemorySsoStore {
    async fn create(&self, provider: NewSsoProvider) -> Result<SsoProvider, SsoStoreError> {
        let mut providers = self.providers.lock().await;
        if providers
            .values()
            .any(|existing| existing.provider_id == provider.provider_id)
        {
            return Err(SsoStoreError::DuplicateProviderId);
        }
        let provider = provider.into_provider();
        providers.insert(provider.id.clone(), provider.clone());
        Ok(provider)
    }

    async fn list(&self) -> Result<Vec<SsoProvider>, SsoStoreError> {
        let providers = self.providers.lock().await;
        let mut providers = providers.values().cloned().collect::<Vec<_>>();
        providers.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(providers)
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<SsoProvider>, SsoStoreError> {
        Ok(self.providers.lock().await.get(id).cloned())
    }

    async fn find_by_provider_id(
        &self,
        provider_id: &str,
    ) -> Result<Option<SsoProvider>, SsoStoreError> {
        Ok(self
            .providers
            .lock()
            .await
            .values()
            .find(|provider| provider.provider_id == provider_id)
            .cloned())
    }

    async fn update(
        &self,
        id: &str,
        update: SsoProviderUpdate,
    ) -> Result<SsoProvider, SsoStoreError> {
        let mut providers = self.providers.lock().await;
        let Some(existing) = providers.get(id).cloned() else {
            return Err(SsoStoreError::NotFound);
        };
        if let Some(provider_id) = update.provider_id.as_deref()
            && providers.values().any(|provider| {
                provider.id != id && provider.provider_id == provider_id
            })
        {
            return Err(SsoStoreError::DuplicateProviderId);
        }
        let provider = providers.get_mut(id).expect("provider exists");
        provider.issuer = update.issuer.unwrap_or(existing.issuer);
        provider.oidc_config = update.oidc_config.unwrap_or(existing.oidc_config);
        provider.saml_config = update.saml_config.unwrap_or(existing.saml_config);
        provider.provider_id = update.provider_id.unwrap_or(existing.provider_id);
        provider.organization_id = update.organization_id.unwrap_or(existing.organization_id);
        provider.domain = update.domain.unwrap_or(existing.domain);
        provider.domain_verified = update.domain_verified.or(existing.domain_verified);
        Ok(provider.clone())
    }

    async fn delete(&self, id: &str) -> Result<Option<SsoProvider>, SsoStoreError> {
        Ok(self.providers.lock().await.remove(id))
    }

    async fn verify_domain(
        &self,
        id: &str,
        expected_domain: &str,
    ) -> Result<bool, SsoStoreError> {
        let mut providers = self.providers.lock().await;
        let Some(provider) = providers.get_mut(id) else {
            return Ok(false);
        };
        if provider.domain != expected_domain {
            return Ok(false);
        }
        provider.domain_verified = Some(true);
        Ok(true)
    }
}
