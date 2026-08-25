#[cfg(feature = "axum")]
mod authorization;
#[cfg(feature = "axum")]
pub(crate) mod axum;
#[cfg(feature = "axum")]
mod client_admin;
mod config;
#[cfg(feature = "axum")]
mod crypto;
mod endpoints;
mod error;
#[cfg(feature = "axum")]
mod expiration;
mod issuer;
mod logout_hook;
mod memory;
mod model;
mod resource_admin;
mod resource_challenge;
mod runtime_store;
pub(crate) mod schema;
mod store;

#[cfg(feature = "axum")]
pub use axum::*;
#[cfg(feature = "axum")]
pub use client_admin::*;
pub use config::OAuthProviderConfig as OAuthProviderPluginConfig;
pub use config::*;
pub use endpoints::{DEFAULT_OAUTH_PROVIDER_RATE_LIMITS, OAUTH_PROVIDER_ENDPOINTS};
pub use error::{OAuthProviderConfigError, OAuthProviderError};
pub use memory::MemoryOAuthProviderStore;
pub use model::*;
pub use resource_admin::{OAuthProviderResourceAdmin, OAuthProviderResourceAdminUpdateInput};
pub use resource_challenge::*;
pub use store::*;

use crate::{
    AuthConfig, AuthError, AuthPlugin, PluginClientMetadata, PluginDescriptor, PluginMigration,
    PluginRateLimit,
};
use async_trait::async_trait;
use std::{borrow::Cow, fmt, sync::Arc};

#[derive(Clone)]
pub struct OAuthProviderPlugin {
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
    migrations: Vec<PluginMigration>,
    logout: logout_hook::LogoutCoordinator,
}

impl OAuthProviderPlugin {
    pub fn new<S>(config: OAuthProviderConfig, store: S) -> Self
    where
        S: OAuthProviderStore + 'static,
    {
        Self::from_arc(config, Arc::new(store))
    }

    pub fn from_arc(mut config: OAuthProviderConfig, store: Arc<dyn OAuthProviderStore>) -> Self {
        // Invalid mappings are rejected by `validate`; they deliberately contribute no
        // fallback migration so a requested custom schema can never become the default silently.
        let migrations = schema::migration(&config.schema).into_iter().collect();
        config.runtime_instance_id = uuid::Uuid::new_v4();
        let config = Arc::new(config);
        let store = Arc::new(runtime_store::OAuthProviderRuntimeStore::new(
            config.clone(),
            store,
        ));
        Self {
            config,
            store,
            migrations,
            logout: logout_hook::LogoutCoordinator::default(),
        }
    }

    #[cfg(feature = "postgres")]
    pub fn postgres(
        config: OAuthProviderConfig,
        store: crate::postgres::PostgresStore,
    ) -> Result<Self, OAuthProviderConfigError> {
        let store = crate::postgres::PostgresOAuthProviderStore::new(store, &config.schema)?;
        Ok(Self::new(config, store))
    }

    pub fn in_memory(config: OAuthProviderConfig) -> Self {
        Self::new(config, MemoryOAuthProviderStore::default())
    }

    pub fn config(&self) -> &OAuthProviderConfig {
        &self.config
    }

    pub fn store(&self) -> &Arc<dyn OAuthProviderStore> {
        &self.store
    }

    pub fn resource_admin(&self) -> OAuthProviderResourceAdmin {
        OAuthProviderResourceAdmin::new(self.config.clone(), self.store.clone())
    }

    #[cfg(feature = "axum")]
    pub fn client_admin(&self) -> OAuthProviderClientAdmin {
        OAuthProviderClientAdmin::new(self.config.clone(), self.store.clone())
    }

    #[cfg(feature = "axum")]
    pub fn provider_api(
        &self,
        service: Arc<crate::AuthService>,
        request: OAuthProviderApiRequest,
        grant_type: Option<String>,
    ) -> Result<OAuthProviderApi, OAuthProviderError> {
        OAuthProviderApi::new(
            service,
            self.config.clone(),
            self.store.clone(),
            request,
            grant_type,
        )
    }
}

impl fmt::Debug for OAuthProviderPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthProviderPlugin")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AuthPlugin for OAuthProviderPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "oauth-provider",
            display_name: "Better Auth OAuth Provider",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            dependencies: if self.config.disable_jwt_plugin {
                &[]
            } else {
                &["jwt"]
            },
            conflicts: &[],
            endpoints: Cow::Borrowed(OAUTH_PROVIDER_ENDPOINTS),
            cookies: &[],
            rate_limits: DEFAULT_OAUTH_PROVIDER_RATE_LIMITS,
            middleware: &[],
            client: Some(PluginClientMetadata::current(
                "@better-auth/oauth-provider",
                "@better-auth/oauth-provider/client",
                "oauthProviderClient",
            )),
        }
    }

    fn validate(&self, _auth: &AuthConfig) -> Result<(), AuthError> {
        self.config
            .validate()
            .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))
    }

    fn migrations(&self) -> Cow<'_, [PluginMigration]> {
        Cow::Borrowed(&self.migrations)
    }

    async fn before_database_delete(
        &self,
        service: &crate::AuthService,
        record: &crate::DatabaseRecord,
        _context: &crate::DatabaseHookContext,
    ) -> Result<(), AuthError> {
        self.logout
            .prepare(service, &self.config, self.store.as_ref(), record)
            .await;
        Ok(())
    }

    async fn after_database_delete(
        &self,
        service: &crate::AuthService,
        record: &crate::DatabaseRecord,
        _context: &crate::DatabaseHookContext,
    ) -> Result<(), AuthError> {
        self.logout
            .complete(service, &self.config, self.store.as_ref(), record)
            .await;
        Ok(())
    }

    fn rate_limits(&self) -> Vec<PluginRateLimit> {
        let configured = &self.config.rate_limit;
        [
            ("/oauth2/token", configured.token),
            ("/oauth2/authorize", configured.authorize),
            ("/oauth2/introspect", configured.introspect),
            ("/oauth2/revoke", configured.revoke),
            ("/oauth2/register", configured.register),
            ("/oauth2/userinfo", configured.userinfo),
        ]
        .into_iter()
        .filter_map(|(path, rule)| {
            rule.map(|rule| PluginRateLimit {
                path,
                window: rule.window,
                max: rule.max,
            })
        })
        .collect()
    }

    #[cfg(feature = "axum")]
    fn routes(&self, _service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(self.config.clone(), self.store.clone())
    }

    #[cfg(feature = "axum")]
    fn root_routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::root_routes(&service, self.config.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_matches_the_upstream_package() {
        let plugin = OAuthProviderPlugin::in_memory(OAuthProviderConfig::new("/login", "/consent"));
        let descriptor = plugin.descriptor();
        assert_eq!(descriptor.id, "oauth-provider");
        assert_eq!(descriptor.dependencies, &["jwt"]);
        assert_eq!(
            descriptor.client.unwrap().package,
            "@better-auth/oauth-provider"
        );
        assert_eq!(plugin.migrations().len(), 1);
    }

    #[test]
    fn configured_rate_limits_can_be_disabled() {
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.rate_limit.token = None;
        let plugin = OAuthProviderPlugin::in_memory(config);
        assert_eq!(plugin.rate_limits().len(), 5);
        assert!(
            !plugin
                .rate_limits()
                .iter()
                .any(|limit| limit.path == "/oauth2/token")
        );
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_factory_carries_schema_into_store_and_migration() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/lucid_auth_compile_test")
            .unwrap();
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.schema.oauth_client.model_name = Some("OAuth Clients".into());
        config
            .schema
            .oauth_client
            .fields
            .insert("clientId".into(), "clientKey".into());

        let store = crate::postgres::PostgresStore::new(pool);
        let mapped =
            crate::postgres::PostgresOAuthProviderStore::new(store.clone(), &config.schema)
                .unwrap();
        let plugin = OAuthProviderPlugin::postgres(config, store).unwrap();
        let sql = &plugin.migrations()[0].sql;
        assert_eq!(sql.as_ref(), mapped.migration_sql());
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS \"OAuth Clients\""));
        assert!(sql.contains("\"clientKey\" TEXT NOT NULL UNIQUE"));
    }

    #[tokio::test]
    async fn configured_resources_are_seeded_through_the_plugin_store() {
        let identifier = "https://api.example.com";
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.resources = vec![identifier.into()];
        let plugin = OAuthProviderPlugin::in_memory(config);

        let resource = plugin
            .store()
            .find_oauth_resource(identifier)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resource.identifier, identifier);
        assert_eq!(resource.name, identifier);
    }

    #[test]
    fn provider_instances_receive_distinct_remote_jwks_cache_namespaces() {
        let config = OAuthProviderConfig::new("/login", "/consent");
        let first = OAuthProviderPlugin::in_memory(config.clone());
        let second = OAuthProviderPlugin::in_memory(config);
        assert_ne!(
            first.config().runtime_instance_id,
            second.config().runtime_instance_id
        );
    }
}
