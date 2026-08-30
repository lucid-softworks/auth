mod access;
#[cfg(feature = "axum")]
mod account_cookie;
mod account_lifecycle;
pub(crate) mod account_types;
mod admin_update;
mod anonymous;
mod api_key;
mod api_key_cleanup;
mod api_key_policy;
mod api_key_storage;
mod api_key_usage;
mod api_key_verification;
mod audit;
mod change_email;
mod configuration;
mod context_id;
mod cookie_signing;
mod dash;
#[cfg(feature = "axum")]
mod dash_organization;
#[cfg(feature = "axum")]
mod dash_two_factor;
mod dash_events;
#[cfg(feature = "axum")]
mod dash_invitation;
mod database;
#[cfg(feature = "axum")]
mod device_authorization;
#[cfg(feature = "axum")]
mod electron;
mod email_otp;
mod email_password;
mod email_verification;
mod guest;
mod jwt;
mod last_login_method;
#[cfg(feature = "axum")]
pub(crate) mod magic_link;
mod mcp;
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
mod open_api;
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
#[cfg(feature = "axum")]
mod session_binding;
mod session_create;
#[cfg(feature = "axum")]
mod session_http_cache;
mod session_references;
mod session_refresh;
mod session_storage;
mod session_update;
#[cfg(feature = "axum")]
mod scim;
mod siwe;
mod siwe_identity;
#[cfg(test)]
mod siwe_tests;
mod test_utils;
mod two_factor;
mod types;
mod user;
mod user_deletion;
mod username;
mod verification_storage;

use crate::{
    AuthConfig, AuthError, AuthSession, AuthStore, AuthUser, AuthenticationMethod, Principal,
    RateLimitOutcome, RateLimitRequest, SessionWithUser, plugin::PluginRegistry,
    rate_limit::RateLimiter,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use session::{hash_token, random_token};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

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

    pub fn try_new(store: Arc<dyn AuthStore>, mut config: AuthConfig) -> Result<Self, AuthError> {
        let plugin_origins = config
            .plugins
            .iter()
            .flat_map(|plugin| plugin.trusted_origins().into_owned())
            .collect::<Vec<_>>();
        for origin in plugin_origins {
            if !config
                .trusted_origins
                .iter()
                .any(|trusted| trusted.as_str() == origin)
            {
                config.trust_origin(origin)?;
            }
        }
        config.validate()?;
        let plugins = PluginRegistry::build(&config.plugins, &config)?;
        if let Some(provider) = plugins.oauth_provider() {
            provider.bind_database_ids(store.clone(), config.database_id_generation.clone())?;
        }
        store.bind_schema(plugins.schema_catalog().clone())?;
        if let Some(stripe) = plugins.find::<crate::StripePlugin>() {
            stripe
                .initialize_soft_composition(plugins.find::<crate::OrganizationPlugin>().is_some());
        }
        let mut social_providers = plugins.social_providers();
        social_providers.extend(config.social_providers.iter().cloned());
        let rate_limiter = RateLimiter::new(
            &config.rate_limit,
            store.clone(),
            config.database_id_generation.clone(),
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
        let id = "00000000-0000-0000-0000-000000000000".to_owned();
        Some(SessionWithUser {
            session: AuthSession {
                id: id.clone(),
                user_id: id.clone(),
                token: String::new(),
                actor_user_id: None,
                authentication_method: Some(AuthenticationMethod::Password),
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
