use crate::{AuthError, AuthPlugin, PluginClientMetadata, PluginDescriptor};
use async_trait::async_trait;
use std::{borrow::Cow, sync::Arc};

#[cfg(feature = "axum")]
mod axum;
mod catalogs;
mod config;
mod detection;

pub use catalogs::I18nLocales;
pub use config::{
    I18nConfig, I18nConfigError, I18nLocaleContext, I18nLocaleDetection, I18nLocaleResolver,
    I18nTranslations, SyncI18nLocaleResolver, TranslationDictionary, sync_i18n_locale_resolver,
};

#[derive(Debug, Clone)]
pub struct I18nPlugin {
    config: Arc<I18nConfig>,
}

impl I18nPlugin {
    pub fn new(config: I18nConfig) -> Result<Self, I18nConfigError> {
        if config.translations.is_empty() {
            return Err(I18nConfigError);
        }
        Ok(Self {
            config: Arc::new(config),
        })
    }

    pub fn config(&self) -> &I18nConfig {
        &self.config
    }

    pub async fn detect_locale(&self, context: I18nLocaleContext) -> String {
        detection::detect(&self.config, context).await
    }
}

#[async_trait]
impl AuthPlugin for I18nPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "i18n",
            display_name: "Better Auth i18n",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::pinned_upstream(
                "@better-auth/i18n",
                crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
                "@better-auth/i18n",
                "i18n",
            ),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Borrowed(&[]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::official(
                "@better-auth/i18n",
                "@better-auth/i18n/client",
                "i18nClient",
            )),
        }
    }

    fn validate(&self, _config: &crate::AuthConfig) -> Result<(), AuthError> {
        if self.config.translations.is_empty() {
            return Err(AuthError::InvalidConfiguration(I18nConfigError.to_string()));
        }
        Ok(())
    }

    #[cfg(feature = "axum")]
    async fn after_response(
        &self,
        service: &crate::AuthService,
        request: &crate::PluginRequestContext,
        response: ::axum::response::Response,
    ) -> ::axum::response::Response {
        axum::translate_response(service, &self.config, request, response).await
    }

    #[cfg(feature = "axum")]
    fn contributes_on_response(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn descriptor_is_route_storage_and_middleware_free() {
        let config = I18nConfig::new(BTreeMap::from([("en".into(), BTreeMap::new())])).unwrap();
        let plugin = I18nPlugin::new(config).unwrap();
        let descriptor = plugin.descriptor();
        assert_eq!(descriptor.id, "i18n");
        assert_eq!(descriptor.version, "1.7.2");
        assert!(descriptor.dependencies.is_empty());
        assert!(descriptor.endpoints.is_empty());
        assert!(descriptor.cookies.is_empty());
        assert!(descriptor.rate_limits.is_empty());
        assert!(descriptor.middleware.is_empty());
        let client = descriptor.client.unwrap();
        assert_eq!(client.package, "@better-auth/i18n");
        assert_eq!(client.import_path, "@better-auth/i18n/client");
        assert_eq!(client.factory, "i18nClient");
    }
}
