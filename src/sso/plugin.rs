use super::{
    MemorySsoStore, SsoOptions, SsoPrivateKey, SsoPrivateKeyResolver, SsoStore, VERSION,
};
#[cfg(feature = "axum")]
use super::SsoPrivateKeyRequest;
use crate::{
    AuthPlugin, PluginArtifactMetadata, PluginClientMetadata, PluginClientPathMethod,
    PluginDescriptor, PluginEndpoint, PluginHttpMethod, PluginProvenance,
};
use async_trait::async_trait;
use std::{borrow::Cow, collections::BTreeMap, sync::Arc};

const BASE_ENDPOINTS: &[PluginEndpoint] = &[
    endpoint(PluginHttpMethod::Get, "/sso/saml2/sp/metadata", "spMetadata"),
    endpoint(PluginHttpMethod::Post, "/sso/register", "registerSSOProvider"),
    endpoint(PluginHttpMethod::Post, "/sign-in/sso", "signInSSO"),
    endpoint(PluginHttpMethod::Get, "/sso/callback/:providerId", "callbackSSO"),
    endpoint(PluginHttpMethod::Get, "/sso/callback", "callbackSSOShared"),
    endpoint(PluginHttpMethod::Get, "/sso/saml2/sp/acs/:providerId", "acsEndpoint"),
    endpoint(PluginHttpMethod::Post, "/sso/saml2/sp/acs/:providerId", "acsEndpoint"),
    endpoint(PluginHttpMethod::Get, "/sso/saml2/sp/slo/:providerId", "sloEndpoint"),
    endpoint(PluginHttpMethod::Post, "/sso/saml2/sp/slo/:providerId", "sloEndpoint"),
    endpoint(PluginHttpMethod::Post, "/sso/saml2/logout/:providerId", "initiateSLO"),
    endpoint(PluginHttpMethod::Get, "/sso/providers", "listSSOProviders"),
    endpoint(PluginHttpMethod::Get, "/sso/get-provider", "getSSOProvider"),
    endpoint(PluginHttpMethod::Post, "/sso/update-provider", "updateSSOProvider"),
    endpoint(PluginHttpMethod::Post, "/sso/delete-provider", "deleteSSOProvider"),
];

const DOMAIN_ENDPOINTS: &[PluginEndpoint] = &[
    endpoint(
        PluginHttpMethod::Post,
        "/sso/request-domain-verification",
        "requestDomainVerification",
    ),
    endpoint(PluginHttpMethod::Post, "/sso/verify-domain", "verifyDomain"),
];

const CLIENT_PATH_METHODS: &[PluginClientPathMethod] = &[
    PluginClientPathMethod::new("/sso/providers", PluginHttpMethod::Get),
    PluginClientPathMethod::new("/sso/get-provider", PluginHttpMethod::Get),
];

const fn endpoint(
    method: PluginHttpMethod,
    path: &'static str,
    client_method: &'static str,
) -> PluginEndpoint {
    PluginEndpoint {
        method,
        path: Cow::Borrowed(path),
        client_method,
    }
}

#[derive(Clone)]
pub struct SsoPlugin {
    options: SsoOptions,
    store: Arc<dyn SsoStore>,
    private_key_resolver: Option<Arc<dyn SsoPrivateKeyResolver>>,
    user_provisioner: Option<Arc<dyn super::SsoUserProvisioner>>,
    user_resolver: Option<Arc<dyn super::SsoUserResolver>>,
    mutation_guard: Option<Arc<dyn super::SsoProviderMutationGuard>>,
    organization_role_resolver: Option<Arc<dyn super::SsoOrganizationRoleResolver>>,
    default_private_keys: BTreeMap<String, SsoPrivateKey>,
    #[cfg(feature = "axum")]
    dns_resolver: Arc<dyn super::SsoDnsResolver>,
}

impl Default for SsoPlugin {
    fn default() -> Self {
        Self::new(SsoOptions::default())
    }
}

impl std::fmt::Debug for SsoPlugin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SsoPlugin")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl SsoPlugin {
    pub fn new(options: SsoOptions) -> Self {
        Self::with_store(options, Arc::new(MemorySsoStore::new()))
    }

    pub fn with_store(options: SsoOptions, store: Arc<dyn SsoStore>) -> Self {
        if let Err(error) = super::schema::validate(&options) {
            panic!("{error}");
        }
        Self {
            options,
            store,
            private_key_resolver: None,
            user_provisioner: None,
            user_resolver: None,
            mutation_guard: None,
            organization_role_resolver: None,
            default_private_keys: BTreeMap::new(),
            #[cfg(feature = "axum")]
            dns_resolver: Arc::new(super::SystemSsoDnsResolver),
        }
    }

    pub fn options(&self) -> &SsoOptions {
        &self.options
    }

    pub fn store(&self) -> &Arc<dyn SsoStore> {
        &self.store
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn find_auth_provider(
        &self,
        provider_id: &str,
    ) -> Result<Option<super::SsoProvider>, super::SsoStoreError> {
        if let Some(provider) = self
            .options
            .default_sso
            .iter()
            .find(|provider| provider.provider_id == provider_id)
        {
            return Ok(Some(
                provider
                    .clone()
                    .into_provider(self.options.domain_verification),
            ));
        }
        self.store.find_by_provider_id(provider_id).await
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn auth_providers(
        &self,
    ) -> Result<Vec<super::SsoProvider>, super::SsoStoreError> {
        let mut providers = self
            .options
            .default_sso
            .iter()
            .cloned()
            .map(|provider| provider.into_provider(self.options.domain_verification))
            .collect::<Vec<_>>();
        let default_ids = providers
            .iter()
            .map(|provider| provider.provider_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        providers.extend(
            self.store
                .list()
                .await?
                .into_iter()
                .filter(|provider| !default_ids.contains(&provider.provider_id)),
        );
        Ok(providers)
    }

    pub fn with_private_key_resolver(mut self, resolver: Arc<dyn SsoPrivateKeyResolver>) -> Self {
        self.private_key_resolver = Some(resolver);
        self
    }

    pub fn with_user_provisioner(mut self, provisioner: Arc<dyn super::SsoUserProvisioner>) -> Self {
        self.user_provisioner = Some(provisioner);
        self
    }

    pub fn with_user_resolver(mut self, resolver: Arc<dyn super::SsoUserResolver>) -> Self {
        self.user_resolver = Some(resolver);
        self
    }

    pub fn with_provider_mutation_guard(
        mut self,
        guard: Arc<dyn super::SsoProviderMutationGuard>,
    ) -> Self {
        self.mutation_guard = Some(guard);
        self
    }

    pub fn with_organization_role_resolver(
        mut self,
        resolver: Arc<dyn super::SsoOrganizationRoleResolver>,
    ) -> Self {
        self.organization_role_resolver = Some(resolver);
        self
    }

    #[cfg(feature = "axum")]
    pub(crate) fn organization_role_resolver(
        &self,
    ) -> Option<&Arc<dyn super::SsoOrganizationRoleResolver>> {
        self.organization_role_resolver.as_ref()
    }

    #[cfg(feature = "axum")]
    pub(crate) fn has_provider_mutation_guard(&self) -> bool {
        self.mutation_guard.is_some()
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn guard_provider_mutation(
        &self,
        input: super::SsoProviderMutationGuardInput,
        database: Arc<dyn crate::DatabaseTransaction>,
    ) -> Result<(), crate::AuthError> {
        let Some(guard) = &self.mutation_guard else {
            return Ok(());
        };
        guard
            .guard(
                input,
                super::SsoProviderMutationGuardContext { database },
            )
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "SSO provider mutation guard rejected mutation");
                crate::AuthError::SsoProviderMutationRejected
            })
    }

    #[cfg(feature = "axum")]
    pub(crate) fn has_user_resolver(&self) -> bool {
        self.user_resolver.is_some()
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn resolve_user(
        &self,
        input: super::SsoUserResolutionInput,
        database: Arc<dyn crate::DatabaseTransaction>,
        directory_pairing_enabled: bool,
    ) -> Result<super::SsoUserResolution, crate::AuthError> {
        if directory_pairing_enabled {
            let paired = super::directory_pairing::resolve(&input, database.clone()).await?;
            if !matches!(paired, super::SsoUserResolution::Continue) {
                return Ok(paired);
            }
        }
        let Some(resolver) = &self.user_resolver else {
            return Ok(super::SsoUserResolution::Continue);
        };
        let resolution = resolver
            .resolve(input, super::SsoUserResolutionContext { database })
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "SSO user resolution failed");
                crate::AuthError::SsoUserResolutionFailed
            })?;
        match &resolution {
            super::SsoUserResolution::Link { user_id, .. } if user_id.trim().is_empty() => {
                Err(crate::AuthError::SsoUserResolutionFailed)
            }
            super::SsoUserResolution::Reject { code, .. } if code.trim().is_empty() => {
                Err(crate::AuthError::SsoUserResolutionFailed)
            }
            _ => Ok(resolution),
        }
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn provision_user(
        &self,
        input: super::SsoProvisioningInput,
        is_new_user: bool,
    ) -> Result<(), crate::AuthError> {
        if !is_new_user && !self.options.provision_user_on_every_login {
            return Ok(());
        }
        match &self.user_provisioner {
            Some(provisioner) => provisioner.provision(input).await,
            None => Ok(()),
        }
    }

    pub fn with_default_private_key(
        mut self,
        provider_id: impl Into<String>,
        private_key: SsoPrivateKey,
    ) -> Self {
        self.default_private_keys
            .insert(provider_id.into(), private_key);
        self
    }

    #[cfg(feature = "axum")]
    pub(crate) fn has_private_key_source(&self, provider_id: &str) -> bool {
        self.options
            .default_sso
            .iter()
            .any(|provider| provider.provider_id == provider_id && provider.private_key.is_some())
            || self.default_private_keys.contains_key(provider_id)
            || self.private_key_resolver.is_some()
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn resolve_private_key(
        &self,
        request: SsoPrivateKeyRequest,
    ) -> Result<Option<SsoPrivateKey>, crate::AuthError> {
        if let Some(material) = self
            .options
            .default_sso
            .iter()
            .find(|provider| provider.provider_id == request.provider_id)
            .and_then(|provider| provider.private_key.as_ref())
        {
            return Ok(Some(material.clone()));
        }
        if let Some(material) = self.default_private_keys.get(&request.provider_id) {
            return Ok(Some(material.clone()));
        }
        match &self.private_key_resolver {
            Some(resolver) => resolver.resolve(request).await,
            None => Ok(None),
        }
    }

    #[cfg(feature = "axum")]
    pub fn with_dns_resolver(mut self, resolver: Arc<dyn super::SsoDnsResolver>) -> Self {
        self.dns_resolver = resolver;
        self
    }

    #[cfg(feature = "axum")]
    pub(crate) fn dns_resolver(&self) -> &Arc<dyn super::SsoDnsResolver> {
        &self.dns_resolver
    }
}

#[async_trait]
impl AuthPlugin for SsoPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        let mut endpoints = BASE_ENDPOINTS.to_vec();
        if self.options.domain_verification {
            endpoints.extend_from_slice(DOMAIN_ENDPOINTS);
        }
        PluginDescriptor {
            id: "sso",
            display_name: "Better Auth Enterprise SSO",
            version: VERSION,
            provenance: PluginProvenance::better_auth(PluginArtifactMetadata::new(
                "@better-auth/sso",
                VERSION,
                "@better-auth/sso",
                "sso",
            )),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Owned(endpoints),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(
                PluginClientMetadata::official(
                    "@better-auth/sso",
                    "@better-auth/sso/client",
                    "ssoClient",
                )
                .with_identity("sso-client", VERSION)
                .with_path_methods(CLIENT_PATH_METHODS),
            ),
        }
    }

    fn schema(&self) -> Vec<crate::PluginSchemaTable> {
        vec![super::schema::table(&self.options)]
    }

    fn request_security(
        &self,
        method: PluginHttpMethod,
        path: &str,
    ) -> crate::PluginRequestSecurity {
        let is_idp_post = ["/sso/saml2/sp/acs/", "/sso/saml2/sp/slo/"]
            .iter()
            .any(|prefix| {
                path.strip_prefix(prefix)
                    .is_some_and(|provider_id| !provider_id.is_empty() && !provider_id.contains('/'))
            });
        if method == PluginHttpMethod::Post && is_idp_post {
            crate::PluginRequestSecurity::RawPublic
        } else {
            crate::PluginRequestSecurity::Browser
        }
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        super::axum::routes(service, Arc::new(self.clone()))
    }
}
