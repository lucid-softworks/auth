use super::{McpPluginConfig, McpPluginConfigError};
use crate::{
    AuthConfig, AuthError, AuthPlugin, OAuthProviderPlugin, OAuthProviderPluginConfig,
    OAuthProviderStore, PluginDescriptor, PluginMigration, PluginRateLimit,
};
use async_trait::async_trait;
use std::{borrow::Cow, fmt, sync::Arc};

#[derive(Clone)]
pub struct McpPlugin {
    config: Arc<McpPluginConfig>,
    provider: OAuthProviderPlugin,
}

impl McpPlugin {
    pub fn new<S>(config: McpPluginConfig, store: S) -> Result<Self, McpPluginBuildError>
    where
        S: OAuthProviderStore + 'static,
    {
        Self::from_arc(config, Arc::new(store))
    }

    pub fn from_arc(
        config: McpPluginConfig,
        store: Arc<dyn OAuthProviderStore>,
    ) -> Result<Self, McpPluginBuildError> {
        let provider_config = config.effective_oauth_provider()?;
        Ok(Self {
            config: Arc::new(config),
            provider: OAuthProviderPlugin::from_arc(provider_config, store),
        })
    }

    pub fn in_memory(config: McpPluginConfig) -> Result<Self, McpPluginBuildError> {
        Self::new(config, crate::MemoryOAuthProviderStore::new())
    }

    #[cfg(feature = "postgres")]
    pub fn postgres(
        config: McpPluginConfig,
        store: crate::postgres::PostgresStore,
    ) -> Result<Self, McpPluginBuildError> {
        let provider_config = config.effective_oauth_provider()?;
        let provider = OAuthProviderPlugin::postgres(provider_config, store)?;
        Ok(Self {
            config: Arc::new(config),
            provider,
        })
    }

    pub fn config(&self) -> &McpPluginConfig {
        &self.config
    }

    pub fn oauth_provider_config(&self) -> &OAuthProviderPluginConfig {
        self.provider.config()
    }

    pub fn provider(&self) -> &OAuthProviderPlugin {
        &self.provider
    }

    pub fn store(&self) -> &Arc<dyn OAuthProviderStore> {
        self.provider.store()
    }

    pub fn resource_admin(&self) -> crate::OAuthProviderResourceAdmin {
        self.provider.resource_admin()
    }

    #[cfg(feature = "axum")]
    pub fn client_admin(&self) -> crate::OAuthProviderClientAdmin {
        self.provider.client_admin()
    }

    #[cfg(feature = "axum")]
    pub fn provider_api(
        &self,
        service: Arc<crate::AuthService>,
        request: crate::OAuthProviderApiRequest,
        grant_type: Option<String>,
    ) -> Result<crate::OAuthProviderApi, crate::OAuthProviderError> {
        self.provider.provider_api(service, request, grant_type)
    }
}

impl fmt::Debug for McpPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpPlugin")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AuthPlugin for McpPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        let mut descriptor = self.provider.descriptor();
        descriptor.display_name = "Better Auth MCP";
        descriptor.provenance = crate::PluginProvenance::pinned_upstream(
            "@better-auth/mcp",
            crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            "@better-auth/mcp",
            "mcp",
        );
        descriptor
    }

    fn validate(&self, auth: &AuthConfig) -> Result<(), AuthError> {
        self.config
            .validate()
            .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?;
        self.provider.validate(auth)
    }

    fn migrations(&self) -> Cow<'_, [PluginMigration]> {
        self.provider.migrations()
    }

    fn rate_limits(&self) -> Vec<PluginRateLimit> {
        self.provider.rate_limits()
    }

    async fn before_database_delete(
        &self,
        service: &crate::AuthService,
        record: &crate::DatabaseRecord,
        context: &crate::DatabaseHookContext,
    ) -> Result<(), AuthError> {
        self.provider
            .before_database_delete(service, record, context)
            .await
    }

    async fn after_database_delete(
        &self,
        service: &crate::AuthService,
        record: &crate::DatabaseRecord,
        context: &crate::DatabaseHookContext,
    ) -> Result<(), AuthError> {
        self.provider
            .after_database_delete(service, record, context)
            .await
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        self.provider.routes(service)
    }

    #[cfg(feature = "axum")]
    fn root_routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        let effective = self.provider.effective_config(&service);
        let mut routes = self.provider.root_routes(service.clone());
        routes.extend(super::axum::root_routes(
            service,
            effective,
            self.config.resource.clone(),
        ));
        routes
    }
}

#[derive(Debug, thiserror::Error)]
pub enum McpPluginBuildError {
    #[error(transparent)]
    Mcp(#[from] McpPluginConfigError),
    #[cfg(feature = "postgres")]
    #[error(transparent)]
    OAuthProvider(#[from] crate::OAuthProviderConfigError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin() -> McpPlugin {
        McpPlugin::in_memory(McpPluginConfig::new(
            "https://api.example.test/mcp",
            OAuthProviderPluginConfig::new("/login", "/consent"),
        ))
        .unwrap()
    }

    #[test]
    fn mcp_preserves_oauth_provider_surface_with_truthful_server_identity() {
        let plugin = plugin();
        let descriptor = plugin.descriptor();
        assert_eq!(descriptor.id, "oauth-provider");
        assert_ne!(
            descriptor.provenance,
            plugin.provider.descriptor().provenance
        );
        let crate::PluginProvenance::PinnedBetterAuthPort { server, .. } = descriptor.provenance
        else {
            panic!("MCP must be a pinned Better Auth port");
        };
        assert_eq!(server.package, "@better-auth/mcp");
        assert_eq!(server.export, "mcp");
        assert_eq!(descriptor.client.unwrap().factory, "oauthProviderClient");
        assert_eq!(plugin.migrations().len(), 1);
        assert_eq!(plugin.rate_limits().len(), 6);
    }

    #[cfg(feature = "axum")]
    #[test]
    fn oauth_provider_companions_resolve_the_mcp_provider() {
        let mut config = AuthConfig::new([42; 32]).unwrap();
        config.add_plugin(crate::JwtPlugin::default()).unwrap();
        config.add_plugin(plugin()).unwrap();
        config
            .add_plugin(crate::OAuthDeviceAuthorizationPlugin::in_memory(
                crate::DeviceAuthorizationConfig::default(),
            ))
            .unwrap();
        let service =
            crate::AuthService::try_new(Arc::new(crate::MemoryStore::default()), config).unwrap();

        assert_eq!(
            service.oauth_provider_plugin().unwrap().config().resources[0].identifier,
            "https://api.example.test/mcp"
        );
    }
}
