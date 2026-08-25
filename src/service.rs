mod access;
#[cfg(feature = "axum")]
mod account_cookie;
mod account_lifecycle;
pub(crate) mod account_types;
mod admin_update;
mod anonymous;
mod api_key;
mod api_key_policy;
mod audit;
mod change_email;
mod cookie_signing;
mod database;
#[cfg(feature = "axum")]
mod device_authorization;
mod email_otp;
mod email_password;
mod email_verification;
mod guest;
mod jwt;
mod last_login_method;
#[cfg(feature = "axum")]
pub(crate) mod magic_link;
#[cfg(feature = "axum")]
mod multi_session;
mod oauth;
mod oauth_identity;
#[cfg(feature = "axum")]
mod oauth_provider;
#[cfg(feature = "axum")]
mod oauth_proxy;
mod oauth_sign_in;
mod oauth_state;
mod oauth_tokens;
mod one_tap;
mod one_time_token;
mod operator_security;
mod organization;
mod passkey;
mod password;
mod password_reset;
mod phone_number;
#[cfg(feature = "axum")]
mod plugin_session;
#[cfg(feature = "axum")]
mod provider_logout;
mod provider_refresh;
mod recovery;
mod session;
mod session_create;
#[cfg(feature = "axum")]
mod session_http_cache;
mod session_references;
mod session_refresh;
mod session_storage;
mod session_update;
mod siwe;
mod siwe_identity;
#[cfg(test)]
mod siwe_tests;
mod two_factor;
mod types;
mod user;
mod user_deletion;
mod username;
mod verification_storage;

#[cfg(feature = "axum")]
use crate::TrustedOrigin;
#[cfg(feature = "axum")]
use crate::cookie::{CookieKind, ResolvedCookie};
use crate::{
    AuthConfig, AuthError, AuthSession, AuthStore, AuthUser, AuthenticationMethod,
    PluginDescriptor, PluginMigrationContribution, Principal, RateLimitOutcome, RateLimitRequest,
    SessionWithUser, plugin::PluginRegistry, rate_limit::RateLimiter,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use session::{hash_token, random_token};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub use api_key::{ApiKeySortDirection, ApiKeyUpdate};
#[cfg(feature = "axum")]
pub(crate) use cookie_signing::decode_cookie_component;
#[cfg(feature = "axum")]
pub(crate) use email_password::valid_email;
pub use email_password::{EmailSignUpInput, EmailSignUpResult};
pub use email_verification::EmailVerificationResult;
pub use oauth::{SocialIdTokenInput, SocialSignInInput, SocialSignInResult};
pub use oauth_state::OAuthCallbackResult;
#[cfg(feature = "axum")]
pub(crate) use oauth_state::OAuthState;
pub use passkey::{
    PasskeyRegistrationRequest, PasskeyRegistrationResult, PasskeyRegistrationVerification,
};
pub use password::PasswordChangeResult;
#[cfg(feature = "axum")]
pub(crate) use two_factor::{
    BackupCodeVerification, TwoFactorEnableResult, TwoFactorSignInOutcome, TwoFactorVerification,
};
pub use types::{HashedPasswordUser, SignInResult};
pub use user_deletion::DeleteUserResult;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct AuthService {
    store: Arc<dyn AuthStore>,
    config: Arc<AuthConfig>,
    plugins: Arc<PluginRegistry>,
    social_providers: Vec<Arc<dyn crate::SocialProvider>>,
    rate_limiter: Arc<RateLimiter>,
    pending_stateless_sessions: Arc<Mutex<HashMap<String, SessionWithUser>>>,
}

impl AuthService {
    pub fn new(store: Arc<dyn AuthStore>, config: AuthConfig) -> Self {
        Self::try_new(store, config)
            .unwrap_or_else(|error| panic!("invalid authentication configuration: {error}"))
    }

    pub fn try_new(store: Arc<dyn AuthStore>, config: AuthConfig) -> Result<Self, AuthError> {
        config.validate()?;
        let plugins = PluginRegistry::build(&config.plugins, &config)?;
        let mut social_providers = plugins.social_providers();
        social_providers.extend(config.social_providers.iter().cloned());
        let rate_limiter = RateLimiter::new(
            &config.rate_limit,
            store.clone(),
            plugins.rate_limits(),
            config.secondary_storage.clone(),
        );
        Ok(Self {
            store,
            config: Arc::new(config),
            plugins: Arc::new(plugins),
            social_providers,
            rate_limiter: Arc::new(rate_limiter),
            pending_stateless_sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

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
    pub(crate) fn plugins(&self) -> &PluginRegistry {
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
    fn resolve_cookie(&self, kind: CookieKind) -> ResolvedCookie {
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

    /// Resolves Better Auth client-IP headers for custom HTTP integrations.
    pub fn resolve_client_ip<F>(&self, header: F) -> Option<String>
    where
        F: FnMut(&str) -> Option<String>,
    {
        self.config.ip_address.resolve_client_ip(header)
    }

    /// Applies Better Auth request rate limiting for a framework integration.
    pub async fn consume_rate_limit_request(
        &self,
        request: &RateLimitRequest,
        client_ip: Option<&str>,
    ) -> Result<Option<RateLimitOutcome>, AuthError> {
        if !self.config.rate_limit.enabled
            || (client_ip.is_none() && self.config.ip_address.disable_ip_tracking)
        {
            return Ok(None);
        }
        let Some(rule) = self
            .config
            .rate_limit
            .resolve_rule(request, self.plugins.rate_limit(&request.path))
            .await?
        else {
            return Ok(None);
        };
        let key = format!("{}|{}", client_ip.unwrap_or("no-trusted-ip"), request.path);
        self.rate_limiter.consume(&key, rule).await.map(Some)
    }

    pub fn development_session(&self) -> Option<SessionWithUser> {
        if !self.config.development_bypass {
            return None;
        }
        let now = Utc::now();
        let id = Uuid::nil();
        Some(SessionWithUser {
            session: AuthSession {
                id,
                user_id: id,
                token: String::new(),
                actor_user_id: None,
                authentication_method: AuthenticationMethod::Password,
                expires_at: now + Duration::days(1),
                created_at: now,
                updated_at: now,
                ip_address: None,
                user_agent: None,
                additional_fields: serde_json::Map::new(),
            },
            user: AuthUser {
                id,
                username: Some("local".into()),
                display_username: Some("Local development".into()),
                name: "Local application".into(),
                email: "local@users.localhost".into(),
                email_verified: false,
                image: None,
                additional_fields: serde_json::Map::new(),
                role: self.default_user_role(),
                is_anonymous: false,
                banned: false,
                ban_reason: None,
                ban_expires: None,
                created_at: now,
                updated_at: now,
            },
        })
    }

    pub async fn session(&self, token: &str) -> Result<Option<SessionWithUser>, AuthError> {
        self.validated_stored_session(token, true).await
    }

    pub async fn principal(&self, token: &str) -> Result<Option<Principal>, AuthError> {
        let Some(session) = self.session(token).await? else {
            return Ok(None);
        };
        self.plugins.authorize_application_access(&session).await?;
        let mut principal = session.principal();
        self.plugins.project_principal(&session, &mut principal);
        Ok(Some(principal))
    }

    pub async fn sign_out(&self, token: &str) -> Result<(), AuthError> {
        self.delete_session_token_with_hooks(token).await
    }

    fn sign(&self, value: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.config.secret)
            .expect("HMAC accepts arbitrary key lengths");
        mac.update(value);
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    pub(crate) async fn require_admin_permission(
        &self,
        session: &SessionWithUser,
        resource: &str,
        actions: &[&str],
    ) -> Result<(), AuthError> {
        crate::admin::require_permission(self.admin_config()?, session, resource, actions)?;
        self.plugins
            .authorize_sensitive(&crate::SensitiveOperation {
                session,
                operation: "admin",
            })
            .await?;
        Ok(())
    }
}
