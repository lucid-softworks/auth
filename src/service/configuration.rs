use super::AuthService;
use crate::{AuthError, PluginDescriptor, PluginMigrationContribution};
use chrono::Duration;
use std::sync::Arc;

#[cfg(feature = "axum")]
use crate::{
    TrustedOrigin,
    cookie::{CookieKind, ResolvedCookie},
};

impl AuthService {
    pub fn plugin_metadata(&self) -> &[PluginDescriptor] {
        self.plugins.descriptors()
    }

    pub fn plugin_migrations(&self) -> Vec<PluginMigrationContribution> {
        self.plugins.migrations()
    }

    pub fn database_schema_fields(
        &self,
        model: crate::DatabaseModel,
    ) -> &crate::AdditionalFieldSet {
        self.plugins.schema_fields(model)
    }

    /// Returns the exact ordered Better Auth schema used by this service.
    pub fn database_schema(&self) -> &crate::AuthSchemaCatalog {
        self.plugins.schema_catalog()
    }

    /// Returns Better Auth's non-plural generic `getSchema` projection.
    pub fn generic_database_schema(&self) -> crate::GenericDatabaseSchema {
        self.database_schema().generic_schema()
    }

    #[cfg(feature = "axum")]
    pub(crate) fn secondary_storage(&self) -> Option<Arc<dyn crate::SecondaryStorage>> {
        self.config.secondary_storage.clone()
    }

    pub(crate) fn admin_plugin(&self) -> Result<&crate::AdminPlugin, AuthError> {
        self.plugins.find::<crate::AdminPlugin>().ok_or_else(|| {
            AuthError::InvalidConfiguration("the admin plugin is not enabled".into())
        })
    }

    pub(crate) fn admin_config(&self) -> Result<&crate::AdminConfig, AuthError> {
        self.admin_plugin().map(crate::AdminPlugin::config)
    }

    pub(crate) fn one_tap_config(&self) -> Result<&crate::OneTapConfig, AuthError> {
        self.plugins
            .find::<crate::OneTapPlugin>()
            .map(crate::OneTapPlugin::config)
            .ok_or_else(|| {
                AuthError::InvalidConfiguration("the one-tap plugin is not enabled".into())
            })
    }

    pub(crate) fn siwe_plugin(&self) -> Result<&crate::SiwePlugin, AuthError> {
        self.plugins
            .find::<crate::SiwePlugin>()
            .ok_or_else(|| AuthError::InvalidConfiguration("the SIWE plugin is not enabled".into()))
    }

    pub(crate) fn social_provider(&self, id: &str) -> Option<&Arc<dyn crate::SocialProvider>> {
        self.social_providers
            .iter()
            .find(|provider| provider.id() == id)
    }

    #[cfg(feature = "axum")]
    pub(crate) fn social_provider_for_logout(
        &self,
        id: &str,
    ) -> Option<&Arc<dyn crate::SocialProvider>> {
        self.social_providers
            .iter()
            .rev()
            .find(|provider| provider.id() == id)
    }

    pub(crate) fn default_user_role(&self) -> String {
        self.plugins
            .find::<crate::AdminPlugin>()
            .map(|plugin| plugin.config().default_role.clone())
            .unwrap_or_else(|| "user".into())
    }

    /// Returns the native API owned by the optional step-up policy plugin.
    pub fn step_up_policy(&self) -> Option<crate::StepUpPolicyService<'_>> {
        self.plugins
            .find::<crate::StepUpPolicyPlugin>()
            .map(|_| crate::StepUpPolicyService::new(self))
    }

    /// Returns the native API owned by the optional operator-security plugin.
    pub fn operator_security(&self) -> Option<crate::OperatorSecurityService<'_>> {
        self.plugins
            .find::<crate::OperatorSecurityPlugin>()
            .map(|_| crate::OperatorSecurityService::new(self))
    }

    #[cfg(feature = "axum")]
    pub(crate) fn plugins(&self) -> &crate::plugin::PluginRegistry {
        &self.plugins
    }

    pub fn session_ttl(&self) -> Duration {
        self.config.session_ttl
    }

    pub fn cookie_secure(&self) -> bool {
        self.config.use_secure_cookies.unwrap_or_else(|| {
            self.config
                .base_url
                .as_ref()
                .is_some_and(|url| url.scheme() == "https")
        })
    }

    #[cfg(feature = "axum")]
    pub(crate) fn trusted_proxy_headers(&self) -> bool {
        self.config.trusted_proxy_headers
    }

    #[cfg(feature = "axum")]
    pub(crate) fn skip_trailing_slashes(&self) -> bool {
        self.config.skip_trailing_slashes
    }

    #[cfg(feature = "axum")]
    pub(crate) fn base_path(&self) -> &str {
        self.config.base_path()
    }

    #[cfg(feature = "axum")]
    pub(crate) fn cors_enabled(&self) -> bool {
        self.config.cors_enabled
    }

    #[cfg(feature = "axum")]
    pub(crate) fn session_cookie(&self) -> ResolvedCookie {
        self.resolve_cookie(CookieKind::SessionToken)
    }

    #[cfg(feature = "axum")]
    pub(crate) fn passkey_challenge_cookie(&self, suffix: &str) -> ResolvedCookie {
        self.config.cookies.resolve_with_suffix(
            CookieKind::PasskeyChallenge,
            Some(suffix),
            self.cookie_secure(),
            self.config.base_url.as_ref().and_then(|url| url.host_str()),
        )
    }

    #[cfg(feature = "axum")]
    pub(crate) fn plugin_cookie(&self, suffix: &str) -> ResolvedCookie {
        self.config.cookies.resolve_with_suffix(
            CookieKind::Plugin,
            Some(suffix),
            self.cookie_secure(),
            self.config.base_url.as_ref().and_then(|url| url.host_str()),
        )
    }

    #[cfg(feature = "axum")]
    pub(super) fn resolve_cookie(&self, kind: CookieKind) -> ResolvedCookie {
        self.config.cookies.resolve(
            kind,
            self.cookie_secure(),
            self.config.base_url.as_ref().and_then(|url| url.host_str()),
        )
    }

    #[cfg(feature = "axum")]
    pub(crate) fn trusts_origin(&self, origin: &str) -> bool {
        self.config.base_url.as_ref().is_some_and(|url| {
            TrustedOrigin::parse(&url.origin().ascii_serialization())
                .is_ok_and(|trusted| trusted.matches(origin))
        }) || self
            .config
            .trusted_origins
            .iter()
            .any(|trusted| trusted.matches(origin))
    }
}
