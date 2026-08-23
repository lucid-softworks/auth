mod access;
mod api_key;
mod api_key_policy;
mod email_password;
mod email_verification;
mod guest;
#[cfg(feature = "axum")]
pub(crate) mod magic_link;
mod passkey;
mod password;
mod password_reset;
mod recovery;
mod session;
mod session_create;
mod two_factor;
mod user;
mod user_deletion;
mod username;

#[cfg(feature = "axum")]
use crate::TrustedOrigin;
#[cfg(feature = "axum")]
use crate::cookie::{CookieKind, ResolvedCookie};
use crate::{
    AuthConfig, AuthError, AuthSession, AuthStore, AuthUser, AuthenticationMethod,
    PluginDescriptor, PluginMigrationContribution, Principal, SessionWithUser,
    plugin::PluginRegistry,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use session::{hash_token, random_token};
use sha2::Sha256;
#[cfg(feature = "axum")]
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

pub use api_key::{ApiKeySortDirection, ApiKeyUpdate};
pub use email_password::{EmailSignUpInput, EmailSignUpResult};
pub use email_verification::EmailVerificationResult;
pub use passkey::{
    PasskeyRegistrationRequest, PasskeyRegistrationResult, PasskeyRegistrationVerification,
};
pub use password::PasswordChangeResult;
#[cfg(feature = "axum")]
pub(crate) use two_factor::{
    BackupCodeVerification, TwoFactorEnableResult, TwoFactorSignInOutcome, TwoFactorVerification,
};
pub use user_deletion::DeleteUserResult;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct SignInResult {
    pub token: String,
    pub session: SessionWithUser,
}

/// Closed-registration account provisioned from an existing Argon2 password hash.
#[derive(Debug, Clone)]
pub struct HashedPasswordUser {
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub role: String,
    pub must_change_password: bool,
}

#[derive(Clone)]
pub struct AuthService {
    store: Arc<dyn AuthStore>,
    config: Arc<AuthConfig>,
    plugins: Arc<PluginRegistry>,
}

impl AuthService {
    pub fn new(store: Arc<dyn AuthStore>, config: AuthConfig) -> Self {
        Self::try_new(store, config)
            .unwrap_or_else(|error| panic!("invalid authentication configuration: {error}"))
    }

    pub fn try_new(store: Arc<dyn AuthStore>, config: AuthConfig) -> Result<Self, AuthError> {
        config.validate()?;
        let plugins = PluginRegistry::build(&config.plugins, &config)?;
        Ok(Self {
            store,
            config: Arc::new(config),
            plugins: Arc::new(plugins),
        })
    }

    pub fn plugin_metadata(&self) -> &[PluginDescriptor] {
        self.plugins.descriptors()
    }

    pub fn plugin_migrations(&self) -> Vec<PluginMigrationContribution> {
        self.plugins.migrations()
    }

    /// Returns the native API owned by the optional step-up policy plugin.
    pub fn step_up_policy(&self) -> Option<crate::StepUpPolicyService<'_>> {
        self.plugins
            .find::<crate::StepUpPolicyPlugin>()
            .map(|_| crate::StepUpPolicyService::new(self))
    }

    #[cfg(feature = "axum")]
    pub(crate) fn plugins(&self) -> &PluginRegistry {
        &self.plugins
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn plugin_session(
        &self,
        headers: &axum::http::HeaderMap,
    ) -> Result<Option<crate::plugin::PluginSession>, AuthError> {
        self.plugins.session_from_headers(self, headers).await
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

    #[cfg(feature = "axum")]
    pub(crate) fn resolve_client_ip<F>(&self, peer: Option<IpAddr>, header: F) -> Option<String>
    where
        F: FnMut(&str) -> Option<String>,
    {
        self.config.ip_address.resolve_client_ip(peer?, header)
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
                token_hash: String::new(),
                actor_user_id: None,
                authentication_method: AuthenticationMethod::Password,
                expires_at: now + Duration::days(1),
                created_at: now,
                updated_at: now,
                ip_address: None,
                user_agent: None,
            },
            user: AuthUser {
                id,
                username: Some("local".into()),
                display_username: Some("Local development".into()),
                name: "Local application".into(),
                email: "local@users.localhost".into(),
                email_verified: false,
                image: None,
                role: "owner".into(),
                is_anonymous: false,
                must_change_password: false,
                banned: false,
                ban_reason: None,
                ban_expires: None,
                created_at: now,
                updated_at: now,
            },
        })
    }

    pub async fn sign_in_anonymous(
        &self,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        if !self.config.allow_anonymous {
            return Err(AuthError::AnonymousAccessDisabled);
        }
        let now = Utc::now();
        let id = Uuid::new_v4();
        let user = self
            .store
            .create_anonymous_user(AuthUser {
                id,
                username: None,
                display_username: None,
                name: "Guest".into(),
                email: format!("temp-{id}@users.localhost"),
                email_verified: false,
                image: None,
                role: "guest".into(),
                is_anonymous: true,
                must_change_password: false,
                banned: false,
                ban_reason: None,
                ban_expires: None,
                created_at: now,
                updated_at: now,
            })
            .await?;
        self.create_session(
            user,
            AuthenticationMethod::Anonymous,
            None,
            ip_address,
            user_agent,
        )
        .await
    }

    pub async fn session(&self, token: &str) -> Result<Option<SessionWithUser>, AuthError> {
        let token_hash = hash_token(token);
        let Some((session, user)) = self.store.find_session(&token_hash).await? else {
            return Ok(None);
        };
        if session.expires_at <= Utc::now() {
            self.store.delete_session(&token_hash).await?;
            return Ok(None);
        }
        if user.banned && user.ban_expires.is_none_or(|expires| expires > Utc::now()) {
            return Ok(None);
        }
        let session = SessionWithUser { session, user };
        if !self.plugins.validates_session(&session).await? {
            self.store.delete_session_by_id(session.session.id).await?;
            return Ok(None);
        }
        Ok(Some(session))
    }

    pub async fn principal(&self, token: &str) -> Result<Option<Principal>, AuthError> {
        let Some(session) = self.session(token).await? else {
            return Ok(None);
        };
        Ok(Some(session.principal()))
    }

    pub async fn sign_out(&self, token: &str) -> Result<(), AuthError> {
        self.store.delete_session(&hash_token(token)).await
    }

    pub fn signed_cookie_value(&self, token: &str) -> String {
        let signature = self.sign(token.as_bytes());
        format!("{token}.{signature}")
    }

    pub fn verify_cookie_value(&self, value: &str) -> Option<String> {
        let (token, signature) = value.rsplit_once('.')?;
        let decoded = URL_SAFE_NO_PAD.decode(signature).ok()?;
        let mut mac = HmacSha256::new_from_slice(&self.config.secret).ok()?;
        mac.update(token.as_bytes());
        mac.verify_slice(&decoded).ok()?;
        Some(token.to_owned())
    }

    async fn enforce_rate_limit(
        &self,
        username: &str,
        ip_address: Option<&str>,
    ) -> Result<(), AuthError> {
        let now = Utc::now();
        let account_limited = self
            .store
            .rate_limit_exceeded(&account_limit_key(username), now, self.config.max_attempts)
            .await?;
        let ip_limited = match ip_address {
            Some(address) => {
                self.store
                    .rate_limit_exceeded(&ip_limit_key(address), now, self.config.max_ip_attempts)
                    .await?
            }
            None => false,
        };
        if account_limited || ip_limited {
            return Err(AuthError::RateLimited);
        }
        Ok(())
    }

    async fn record_failure(
        &self,
        username: &str,
        ip_address: Option<&str>,
    ) -> Result<(), AuthError> {
        let now = Utc::now();
        self.store
            .record_auth_failure(
                &account_limit_key(username),
                now,
                self.config.lockout_window,
            )
            .await?;
        if let Some(address) = ip_address {
            self.store
                .record_auth_failure(&ip_limit_key(address), now, self.config.lockout_window)
                .await?;
        }
        Ok(())
    }

    fn sign(&self, value: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.config.secret)
            .expect("HMAC accepts arbitrary key lengths");
        mac.update(value);
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    async fn require_recent_owner(&self, session: &SessionWithUser) -> Result<(), AuthError> {
        access::require_owner(session)?;
        self.plugins
            .authorize_sensitive(&crate::SensitiveOperation {
                session,
                operation: "owner-administration",
            })
            .await?;
        Ok(())
    }
}

fn account_limit_key(username: &str) -> String {
    format!("sign-in:account:{}", hash_token(username))
}

fn ip_limit_key(address: &str) -> String {
    format!("sign-in:ip:{}", hash_token(address))
}
